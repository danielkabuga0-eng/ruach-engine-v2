from typing import Protocol
from .circuit_breaker import tax_validator
from .tax_rules import EU_MEMBER_STATES

class VATValidationProvider(Protocol):
    async def validate_tax_id(self, tax_id: str, country: str) -> dict: ...

class VIESProvider:
    name = "EU_VIES"
    async def validate(self, tax_id: str, country: str) -> dict:
        return await tax_validator.validate_tax_id(tax_id, country)

class ProviderRegistry:
    """Provider-agnostic validation registry. Additional jurisdiction providers can be added without changing the decision engine."""
    def __init__(self):
        self._providers = {"EU_VIES": VIESProvider()}

    def provider_for(self, country: str) -> VIESProvider | None:
        return self._providers.get("EU_VIES") if country in EU_MEMBER_STATES else None

    async def validate(self, tax_id: str, country: str) -> dict:
        provider = self.provider_for(country)
        if provider is None:
            return {"status": "UNSUPPORTED", "country": country, "reason": "No authoritative provider configured"}
        result = await provider.validate(tax_id, country)
        result["provider"] = provider.name
        return result

providers = ProviderRegistry()
