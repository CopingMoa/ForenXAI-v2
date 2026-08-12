from services.config import CASE_OUTPUT_DIR
from services.model_service import load_model
from views.main_window import MainWindow


def main():
    model = load_model()

    app = MainWindow(model=model, case_output_dir=CASE_OUTPUT_DIR)
    app.run()


if __name__ == "__main__":
    main()


# NEW STRUCTURE
# my_tkinter_app/
# ├── views/
# │   ├── main_window.py      # root window, notebook, wires the 3 tabs together
# │   ├── forensic_tab.py     # Tab 1: drop zone, dashboard cards, pipeline log
# │   ├── xai_tab.py          # Tab 2: SHAP display, investigator review
# │   └── evaluation_tab.py   # Tab 3: labeled-dataset evaluation + confusion matrix
# ├── services/
# │   ├── config.py           # paths (the fix from before)
# │   ├── utils.py             # hashing, timestamps
# │   ├── model_service.py    # model loading, schema validation
# │   ├── zeek_service.py     # zeek parsing, data cleaning
# │   ├── shap_service.py     # SHAP explanation generation
# │   ├── pipeline_service.py # the full 9-stage pcap→prediction→report pipeline
# │   └── evaluation_service.py # accuracy/precision/recall/confusion matrix logic
# └── main.py                 # entry point: loads model, starts the app