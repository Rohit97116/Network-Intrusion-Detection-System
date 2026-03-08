# Datasets Directory

Place training and detection CSV files in this folder.

## Recommended datasets
- `NSL-KDD` (directly supported by default preprocessing)
- `CICIDS2017` (supported if you map columns to the NSL-KDD feature schema before training)

## Expected file formats
- Training:
  - NSL-KDD `KDDTrain+` / `KDDTest+` style files (with or without headers)
  - Must include labels in a `label` column or in NSL-KDD positional format
- Detection:
  - CSV with NSL-KDD feature columns
  - `label` column is optional during detection

## Included examples
- `sample_training_nsl_kdd.csv`: tiny example with labels (for quick API checks)
- `sample_traffic_nsl_kdd.csv`: tiny unlabeled traffic sample (for prediction checks)
