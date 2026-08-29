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
    """

    app = MainWindow(
        case_output_dir=CASE_OUTPUT_DIR,
        default_model="CIDS2018"
    )

    app.run()


if __name__ == "__main__":
    main()