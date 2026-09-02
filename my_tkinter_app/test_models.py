from services.model_service import (
    discover_models,
    get_expected_features,
    load_model
)

print(discover_models())

model = load_model("CIDS2018")

print(type(model))

print(get_expected_features("CIDS2018"))