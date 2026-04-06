"""Config flow for Garmin Connect integration."""

import logging
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
from homeassistant.const import CONF_ID, CONF_TOKEN, CONF_PASSWORD, CONF_USERNAME
import voluptuous as vol

from .const import CONF_MFA, CONF_IMPORT_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)


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

    async def _async_garmin_connect_login(self, step_id: str) -> ConfigFlowResult:
        """Authenticate with Garmin Connect using credentials."""
        errors = {}

        country = self.hass.config.country
        if country == "CN":
            self._in_china = True

        self._api = Garmin(email=self._username,
                           password=self._password, return_on_mfa=True, is_cn=self._in_china)

        try:
            self._login_result1, self._login_result2 = await self.hass.async_add_executor_job(self._api.login)

            if self._login_result1 == "needs_mfa":
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
            _LOGGER.error("HTTP error during Garmin login: %s (status %s)", err, err.response.status_code)
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
                step_id=step_id, data_schema=vol.Schema(self.data_schema), errors=errors
            )

        return await self._async_create_entry()

    async def _async_garmin_connect_mfa_login(self) -> ConfigFlowResult:
        """Complete MFA authentication."""
        try:
            await self.hass.async_add_executor_job(self._api.resume_login, self._login_result2, self._mfa_code)

        except GarminConnectAuthenticationError as err:
            _LOGGER.error("Error during MFA login: %s", err)
            return self.async_show_form(
                step_id="mfa",
                data_schema=vol.Schema(self.mfa_data_schema),
                errors={"base": "invalid_mfa_code"},
            )

        return await self._async_create_entry()

    async def _async_create_entry(self) -> ConfigFlowResult:
        """Create or update the config entry with the current API token."""
        config_data = {
            CONF_ID: self._username,
            CONF_TOKEN: self._api.client.dumps(),
        }
        existing_entry = await self.async_set_unique_id(self._username)

        if existing_entry:
            self.hass.config_entries.async_update_entry(
                existing_entry, data=config_data)
            await self.hass.config_entries.async_reload(existing_entry.entry_id)
            return self.async_abort(reason="reauth_successful")

        return self.async_create_entry(
            title=cast(str, self._username), data=config_data
        )

    async def async_step_user(
            self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show initial menu: login with credentials or import a token."""
        return self.async_show_menu(
            step_id="user",
            menu_options=["credentials", "import_token"],
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

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the MFA step."""
        if user_input is None:
            return self.async_show_form(
                step_id="mfa", data_schema=vol.Schema(self.mfa_data_schema)
            )

        self._mfa_code = user_input[CONF_MFA]
        _LOGGER.debug("MFA code received")

        return await self._async_garmin_connect_mfa_login()

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauthorization."""
        self._username = entry_data.get(
            CONF_USERNAME) or entry_data.get(CONF_ID)

        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth: offer credentials or token import."""
        return self.async_show_menu(
            step_id="reauth_confirm",
            menu_options=["reauth_credentials", "reauth_import_token"],
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
