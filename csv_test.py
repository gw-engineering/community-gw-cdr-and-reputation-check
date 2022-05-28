import pandas as pd

read_file = pd.read_csv (r'csv.csv')
read_file.to_excel (r'excel.xlsx', index = None, header=True)