from services.config import CASE_OUTPUT_DIR

from views.main_window import MainWindow


def main():
    """
    ForenXAI application entry point.

    Model discovery and loading are now handled by
    MainWindow so the user can select between available
    trained datasets/models.

    OLD:
        model = load_model()

    NEW:
        MainWindow discovers available models from:

            my_tkinter_app/artifacts/

        and loads the selected model automatically.

    The default is the 16-class multiclass model, which is the one the XAI
    tab's three panels use. Defaulting to anything else means the Forensic
    tab and the XAI tab report different classes for the same capture --
    which is what happened while CIDS2018 (20 features, 6 classes) was the
    default and the panels ran the multiclass model regardless.

    The legacy CIDS2018 and TII models remain selectable in the dropdown.
    """

    app = MainWindow(
        case_output_dir=CASE_OUTPUT_DIR,
        default_model="ForenXAI-Multiclass"
    )

    app.run()


if __name__ == "__main__":
    main()