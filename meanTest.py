import pandas as pd

def print_column_means(csv_path):
    # Legge il CSV
    df = pd.read_csv(csv_path)

    # Converte tutto ciò che è possibile in numerico
    numeric_df = df.apply(pd.to_numeric, errors="coerce")

    # Calcola media ignorando i NaN
    means = numeric_df.mean()

    # Stampa risultati
    print("\nColumn means:\n")
    for col, value in means.items():
        print(f"{col}: {value}")


if __name__ == "__main__":
    csv_path = r"C:\Users\riovi\Privacy-Homomorphism-App\diabetes.csv"  
    print_column_means(csv_path)