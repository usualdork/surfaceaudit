"""Template variable substitution for v2 rule descriptions."""

from __future__ import annotations

from surfaceaudit.rules.v2.schema import AssetContext

# Maximum length for the {banner_preview} substitution.
_BANNER_PREVIEW_MAX = 80

# Supported template variables and their corresponding AssetContext fields.
_TEMPLATE_VARS: dict[str, str] = {
    "service_name": "service_name",
    "service_version": "service_version",
    "port": "port",
    "ip": "ip",
    "hostname": "hostname",
    "banner_preview": "banner",
}

_DEFAULT = "unknown"


def substitute_template(template: str, context: AssetContext) -> str:
    """Replace template variables with actual values from *context*.

    Supported variables: ``{service_name}``, ``{service_version}``,
    ``{port}``, ``{ip}``, ``{hostname}``, ``{banner_preview}``.

    * ``{banner_preview}`` maps to the ``banner`` field, truncated to the
      first 80 characters when longer.
    * Any variable whose underlying value is ``None`` is replaced with
      ``"unknown"``.
    """
    result = template
    for var, field_name in _TEMPLATE_VARS.items():
        placeholder = "{" + var + "}"
        if placeholder not in result:
            continue

        raw = context.get_field(field_name)

        if raw is None:
            value = _DEFAULT
        else:
            value = str(raw)
            if var == "banner_preview" and len(value) > _BANNER_PREVIEW_MAX:
                value = value[:_BANNER_PREVIEW_MAX]

        result = result.replace(placeholder, value)

    return result
