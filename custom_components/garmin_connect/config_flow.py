"""Config flow for Garmin Connect integration."""

import logging
import os
from collections.abc import Mapping
from typing import Any, cast

import requests
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ID, CONF_PASSWORD, CONF_TOKEN, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .const import (
    ADDON_API_PORT,
    ADDON_SLUG_SUFFIX,
    CONF_ADDON_URL,
    CONF_IMPORT_TOKEN,
    CONF_MFA,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# Timeout for add-on login (browser startup + Cloudflare delays)
_ADDON_LOGIN_TIMEOUT = 300
_ADDON_MFA_TIMEOUT = 300


class GarminConnectConfigFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Garmin Connect."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow handler."""
        self.data_schema = {
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
        }
        self.mfa_data_schema = {
            vol.Required(CONF_MFA): str,
        }
        self.import_token_schema = {
            vol.Required(CONF_IMPORT_TOKEN): str,
        }

        self._api = None
        self._login_result1: Any = None
        self._login_result2: Any = None
        self._mfa_code: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._in_china = False
        self._addon_url: str | None = None
        self._auth_via_addon = False

    async def _discover_addon(self) -> str | None:
        """Discover the Garmin Auth add-on via the Supervisor API.

        Returns the add-on base URL (e.g. http://172.30.33.x:8099) or None.
        """
        supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
        if not supervisor_token:
            return None

        session = async_get_clientsession(self.hass)
        headers = {"Authorization": f"Bearer {supervisor_token}"}

        try:
            resp = await session.get("http://supervisor/addons", headers=headers, timeout=10)
            data = await resp.json()
            addons = data.get("data", {}).get("addons", [])

            slug = None
            for addon in addons:
                if addon.get("slug", "").endswith(ADDON_SLUG_SUFFIX):
                    if addon.get("state") == "started":
                        slug = addon["slug"]
                        break

            if not slug:
                return None

            info_resp = await session.get(
                f"http://supervisor/addons/{slug}/info",
                headers=headers,
                timeout=10,
            )
            info = await info_resp.json()
            ip_address = info.get("data", {}).get("ip_address")
            if not ip_address:
                _LOGGER.warning("Garmin Auth add-on found but has no IP address")
                return None

            url = f"http://{ip_address}:{ADDON_API_PORT}"
            _LOGGER.info("Discovered Garmin Auth add-on at %s", url)
            return url

        except Exception:  # pylint: disable=broad-except
            _LOGGER.debug("Supervisor API unavailable or add-on not found", exc_info=True)
            return None

    async def _addon_login(self) -> dict:
        """Call the add-on's /api/login endpoint.

        Returns the JSON response dict: {status, tokens?} or {status, message}.
        """
        session = async_get_clientsession(self.hass)
        resp = await session.post(
            f"{self._addon_url}/api/login",
            json={"email": self._username, "password": self._password},
            timeout=_ADDON_LOGIN_TIMEOUT,
        )
        return await resp.json()

    async def _addon_mfa(self, code: str) -> dict:
        """Call the add-on's /api/mfa endpoint.

        Returns the JSON response dict: {status, tokens?} or {status, message}.
        """
        session = async_get_clientsession(self.hass)
        resp = await session.post(
            f"{self._addon_url}/api/mfa",
            json={"code": code},
            timeout=_ADDON_MFA_TIMEOUT,
        )
        return await resp.json()

    async def _async_garmin_connect_login(self, step_id: str) -> ConfigFlowResult:
        """Authenticate with Garmin Connect using credentials.

        Tries the Garmin Auth add-on first (if running), then falls back to
        the python-garminconnect login strategies.
        """
        errors = {}

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        # ── Try add-on first ──
        if self._addon_url is None:
            self._addon_url = await self._discover_addon()

        if self._addon_url:
            _LOGGER.info("Attempting login via Garmin Auth add-on")
            try:
                result = await self._addon_login()
                status = result.get("status")

                if status == "needs_mfa":
                    # Create a Garmin instance so _async_create_entry works
                    self._api = Garmin(
                        email=self._username,
                        password=self._password,
                        is_cn=self._in_china,
                    )
                    return await self.async_step_mfa()

                if status == "ok":
                    self._api = Garmin(is_cn=self._in_china)
                    tokens = result.get("tokens", {})
                    self._api.client.jwt_web = tokens.get("jwt_web", "")
                    self._api.client.csrf_token = tokens.get("csrf_token", "")
                    return await self._async_create_entry()

                _LOGGER.warning(
                    "Add-on login failed: %s — falling back to HTTP",
                    result.get("message", "unknown error"),
                )

            except Exception:  # pylint: disable=broad-except
                _LOGGER.warning(
                    "Add-on login error — falling back to HTTP strategies",
                    exc_info=True,
                )

        # ── Fallback: python-garminconnect login strategies ──
        self._api = Garmin(
            email=self._username,
            password=self._password,
            return_on_mfa=True,
            is_cn=self._in_china,
        )

        try:
            self._login_result1, self._login_result2 = await self.hass.async_add_executor_job(
                self._api.login
            )

            if self._login_result1 == "needs_mfa":
                self._auth_via_addon = False
                return await self.async_step_mfa()

        except GarminConnectConnectionError as err:
            _LOGGER.error("Connection error during Garmin login: %s", err)
            errors = {"base": "cannot_connect"}
        except GarminConnectAuthenticationError as err:
            _LOGGER.error("Authentication error during Garmin login: %s", err)
            errors = {"base": "invalid_auth"}
        except GarminConnectTooManyRequestsError as err:
            _LOGGER.error("Rate limited during Garmin login: %s", err)
            errors = {"base": "too_many_requests"}
        except requests.exceptions.HTTPError as err:
            _LOGGER.error(
                "HTTP error during Garmin login: %s (status %s)",
                err,
                err.response.status_code,
            )
            if err.response.status_code == 403:
                errors = {"base": "invalid_auth"}
            elif err.response.status_code == 429:
                errors = {"base": "too_many_requests"}
            else:
                errors = {"base": "cannot_connect"}
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors = {"base": "unknown"}

        if errors:
            return self.async_show_form(
                step_id=step_id,
                data_schema=vol.Schema(self.data_schema),
                errors=errors,
            )

        return await self._async_create_entry()

    async def _async_garmin_connect_mfa_login(self) -> ConfigFlowResult:
        """Complete MFA authentication (add-on or direct)."""
        if self._auth_via_addon:
            return await self._async_addon_mfa_login()

        try:
            await self.hass.async_add_executor_job(
                self._api.resume_login, self._login_result2, self._mfa_code
            )

        except GarminConnectAuthenticationError as err:
            _LOGGER.error("Error during MFA login: %s", err)
            return self.async_show_form(
                step_id="mfa",
                data_schema=vol.Schema(self.mfa_data_schema),
                errors={"base": "invalid_mfa_code"},
            )

        return await self._async_create_entry()

    async def _async_addon_mfa_login(self) -> ConfigFlowResult:
        """Complete MFA via the Garmin Auth add-on."""
        try:
            result = await self._addon_mfa(self._mfa_code)
            status = result.get("status")

            if status == "ok":
                tokens = result.get("tokens", {})
                self._api.client.jwt_web = tokens.get("jwt_web", "")
                self._api.client.csrf_token = tokens.get("csrf_token", "")
                return await self._async_create_entry()

            _LOGGER.error("Add-on MFA failed: %s", result.get("message"))
            return self.async_show_form(
                step_id="mfa",
                data_schema=vol.Schema(self.mfa_data_schema),
                errors={"base": "invalid_mfa_code"},
            )

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Add-on MFA error")
            return self.async_show_form(
                step_id="mfa",
                data_schema=vol.Schema(self.mfa_data_schema),
                errors={"base": "unknown"},
            )

    async def _async_create_entry(self) -> ConfigFlowResult:
        """Create or update the config entry with the current API token."""
        config_data = {
            CONF_ID: self._username,
            CONF_TOKEN: self._api.client.dumps(),
        }

        # When using the add-on, store the URL and password so the
        # coordinator can proxy API calls through the browser add-on
        # and re-login after HA/add-on restarts.
        if self._auth_via_addon and self._addon_url:
            config_data[CONF_ADDON_URL] = self._addon_url
        if self._auth_via_addon and self._password:
            config_data[CONF_PASSWORD] = self._password

        existing_entry = await self.async_set_unique_id(self._username)

        if existing_entry:
            self.hass.config_entries.async_update_entry(existing_entry, data=config_data)
            await self.hass.config_entries.async_reload(existing_entry.entry_id)
            return self.async_abort(reason="reauth_successful")

        return self.async_create_entry(title=cast(str, self._username), data=config_data)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show initial menu: login with credentials or import a token."""
        return self.async_show_menu(
            step_id="user",
            menu_options=["addon_login", "credentials", "import_token"],
        )

    async def async_step_addon_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle browser-based login via the Garmin Auth add-on only."""
        errors = {}

        if user_input is None:
            return self.async_show_form(
                step_id="addon_login", data_schema=vol.Schema(self.data_schema)
            )

        self._username = user_input[CONF_USERNAME]
        self._password = user_input[CONF_PASSWORD]

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        if self._addon_url is None:
            self._addon_url = await self._discover_addon()

        if not self._addon_url:
            _LOGGER.error("Garmin Auth add-on not found or not running")
            errors = {"base": "addon_not_found"}
            return self.async_show_form(
                step_id="addon_login",
                data_schema=vol.Schema(self.data_schema),
                errors=errors,
            )

        try:
            result = await self._addon_login()
            status = result.get("status")

            if status == "needs_mfa":
                self._auth_via_addon = True
                self._api = Garmin(
                    email=self._username,
                    password=self._password,
                    is_cn=self._in_china,
                )
                return await self.async_step_mfa()

            if status == "ok":
                self._auth_via_addon = True
                self._api = Garmin(is_cn=self._in_china)
                tokens = result.get("tokens", {})
                self._api.client.jwt_web = tokens.get("jwt_web", "")
                self._api.client.csrf_token = tokens.get("csrf_token", "")
                return await self._async_create_entry()

            _LOGGER.error("Add-on login failed: %s", result.get("message"))
            errors = {"base": "invalid_auth"}

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Add-on login error")
            errors = {"base": "unknown"}

        return self.async_show_form(
            step_id="addon_login",
            data_schema=vol.Schema(self.data_schema),
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle credential-based login."""
        if user_input is None:
            return self.async_show_form(
                step_id="credentials", data_schema=vol.Schema(self.data_schema)
            )

        self._username = user_input[CONF_USERNAME]
        self._password = user_input[CONF_PASSWORD]

        return await self._async_garmin_connect_login(step_id="credentials")

    async def async_step_import_token(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle token import from garmin-givemydata."""
        errors = {}

        if user_input is None:
            return self.async_show_form(
                step_id="import_token",
                data_schema=vol.Schema(self.import_token_schema),
            )

        token_str = user_input[CONF_IMPORT_TOKEN].strip()

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        self._api = Garmin(is_cn=self._in_china)

        try:
            await self.hass.async_add_executor_job(self._api.login, token_str)

        except GarminConnectAuthenticationError as err:
            _LOGGER.error("Token import auth error: %s", err)
            errors = {"base": "invalid_token"}
        except GarminConnectConnectionError as err:
            _LOGGER.error("Token import connection error: %s", err)
            errors = {"base": "cannot_connect"}
        except GarminConnectTooManyRequestsError as err:
            _LOGGER.error("Token import rate limited: %s", err)
            errors = {"base": "too_many_requests"}
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception during token import")
            errors = {"base": "unknown"}

        if errors:
            return self.async_show_form(
                step_id="import_token",
                data_schema=vol.Schema(self.import_token_schema),
                errors=errors,
            )

        self._username = self._api.display_name or "garmin_user"

        return await self._async_create_entry()

    async def async_step_mfa(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the MFA step."""
        if user_input is None:
            return self.async_show_form(step_id="mfa", data_schema=vol.Schema(self.mfa_data_schema))

        self._mfa_code = user_input[CONF_MFA]
        _LOGGER.debug("MFA code received")

        return await self._async_garmin_connect_mfa_login()

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Start reauthorization."""
        self._username = entry_data.get(CONF_USERNAME) or entry_data.get(CONF_ID)

        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth: offer credentials or token import."""
        return self.async_show_menu(
            step_id="reauth_confirm",
            menu_options=["reauth_addon_login", "reauth_credentials", "reauth_import_token"],
        )

    async def async_step_reauth_addon_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth via the Garmin Auth add-on only."""
        errors = {}

        if user_input is None:
            return self.async_show_form(
                step_id="reauth_addon_login",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_USERNAME, default=self._username): str,
                        vol.Required(CONF_PASSWORD): str,
                    }
                ),
            )

        self._username = user_input[CONF_USERNAME]
        self._password = user_input[CONF_PASSWORD]

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        if self._addon_url is None:
            self._addon_url = await self._discover_addon()

        if not self._addon_url:
            _LOGGER.error("Garmin Auth add-on not found or not running")
            errors = {"base": "addon_not_found"}
            return self.async_show_form(
                step_id="reauth_addon_login",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_USERNAME, default=self._username): str,
                        vol.Required(CONF_PASSWORD): str,
                    }
                ),
                errors=errors,
            )

        try:
            result = await self._addon_login()
            status = result.get("status")

            if status == "needs_mfa":
                self._auth_via_addon = True
                self._api = Garmin(
                    email=self._username,
                    password=self._password,
                    is_cn=self._in_china,
                )
                return await self.async_step_mfa()

            if status == "ok":
                self._auth_via_addon = True
                self._api = Garmin(is_cn=self._in_china)
                tokens = result.get("tokens", {})
                self._api.client.jwt_web = tokens.get("jwt_web", "")
                self._api.client.csrf_token = tokens.get("csrf_token", "")
                return await self._async_create_entry()

            _LOGGER.error("Add-on reauth failed: %s", result.get("message"))
            errors = {"base": "invalid_auth"}

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Add-on reauth error")
            errors = {"base": "unknown"}

        return self.async_show_form(
            step_id="reauth_addon_login",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=self._username): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth with credentials."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_credentials",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_USERNAME, default=self._username): str,
                        vol.Required(CONF_PASSWORD): str,
                    }
                ),
            )

        self._username = user_input[CONF_USERNAME]
        self._password = user_input[CONF_PASSWORD]

        return await self._async_garmin_connect_login(step_id="reauth_credentials")

    async def async_step_reauth_import_token(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth with token import."""
        errors = {}

        if user_input is None:
            return self.async_show_form(
                step_id="reauth_import_token",
                data_schema=vol.Schema(self.import_token_schema),
            )

        token_str = user_input[CONF_IMPORT_TOKEN].strip()

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        self._api = Garmin(is_cn=self._in_china)

        try:
            await self.hass.async_add_executor_job(self._api.login, token_str)

        except GarminConnectAuthenticationError as err:
            _LOGGER.error("Token reauth error: %s", err)
            errors = {"base": "invalid_token"}
        except GarminConnectConnectionError as err:
            _LOGGER.error("Token reauth connection error: %s", err)
            errors = {"base": "cannot_connect"}
        except GarminConnectTooManyRequestsError as err:
            _LOGGER.error("Token reauth rate limited: %s", err)
            errors = {"base": "too_many_requests"}
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception during token reauth")
            errors = {"base": "unknown"}

        if errors:
            return self.async_show_form(
                step_id="reauth_import_token",
                data_schema=vol.Schema(self.import_token_schema),
                errors=errors,
            )

        self._username = self._api.display_name or self._username or "garmin_user"

        return await self._async_create_entry()
