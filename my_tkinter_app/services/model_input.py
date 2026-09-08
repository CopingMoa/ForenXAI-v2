"""
Input conditioning for the deployed multiclass model.

This module exists so the cast below can be PICKLED. The deployed
model.joblib is a sklearn Pipeline whose first step is a
FunctionTransformer wrapping as_float32; joblib stores that by import path,
so the function has to live at a stable module-level location the app can
always import. A lambda, or a function defined inside the deploy script,
would save fine and then fail to load.

WHY THE CAST IS NECESSARY
-------------------------
The model was trained on float32 features -- mc_train_random.parquet is
float32 throughout. Passing float64 at inference gives the model values it
was never fitted against, and the difference is not cosmetic: on a real
6,995-flow capture the two dtypes produced identical feature matrices
(every cell equal to 1e-6) but DIFFERENT predictions on 12.7% of rows.

Boosted trees compare a feature against a stored split threshold. Those
thresholds were learned in float32. A value that rounds to exactly the
threshold in float32 can sit just above or below it in float64, and the row
then takes the other branch. There is no error and no warning -- just a
different class.

So float32 is not a performance choice here, it is the input space the model
was fitted in. Casting makes the Forensic tab and the XAI tab agree exactly,
which they did not before.
"""

import numpy as np


def as_float32(X):
    """
    Cast a feature frame or array to a plain float32 ndarray.

    Dropping the column labels is intentional as well as convenient: the
    StandardScaler in the same Pipeline was fitted on a bare array, so it
    has no feature_names_in_, and handing it a labelled DataFrame makes
    sklearn warn on every single call. Column ORDER is what has to be
    right, and the caller selects columns by the frozen schema before
    reaching this point.
    """

    values = getattr(X, "values", X)

    return np.asarray(values, dtype=np.float32)
