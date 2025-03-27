import argparse
import pandas as pd
import os
import sys
import json
from pathlib import Path

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract data from Excel files with multiple sheets.')
    
    # Required arguments
    parser.add_argument('file', help='Path to the Excel file')
    
    # Optional arguments
    parser.add_argument('-s', '--sheets', nargs='+', help='Specific sheet names to process (default: all sheets)')
    parser.add_argument('-o', '--output', default='output', help='Output directory or file prefix')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'xlsx', 'txt'], default='csv', 
                        help='Output format (default: csv)')
    parser.add_argument('-r', '--rows', type=str, help='Row range to extract (e.g., "5:10")')
    parser.add_argument('-c', '--columns', type=str, help='Column range to extract (e.g., "A:C" or "1:3")')
    parser.add_argument('-q', '--query', type=str, help='SQL-like query to filter data')
    parser.add_argument('-m', '--merge', action='store_true', help='Merge all sheets into one output file')
    parser.add_argument('-i', '--info', action='store_true', help='Display information about the Excel file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()

def get_sheet_names(file_path):
    """Get all sheet names from an Excel file using pandas."""
    try:
        # First try with default engine
        excel_file = pd.ExcelFile(file_path)
        return excel_file.sheet_names
    except Exception as e:
        print(f"Warning: {e}")
        try:
            # Try with xlrd engine for older .xls files
            excel_file = pd.ExcelFile(file_path, engine='xlrd')
            return excel_file.sheet_names
        except Exception as e2:
            print(f"Error reading Excel file: {e2}")
            print("Supported formats are: .xlsx, .xlsm, .xls")
            sys.exit(1)

def process_range(range_str):
    """Process a range string like '5:10' or 'A:C'."""
    if not range_str:
        return None, None
    
    parts = range_str.split(':')
    if len(parts) != 2:
        print(f"Invalid range format: {range_str}. Expected format like '5:10' or 'A:C'.")
        return None, None
    
    return parts[0], parts[1]

def convert_column_letter_to_index(column_letter):
    """Convert Excel column letter to zero-based index."""
    if column_letter.isdigit():
        return int(column_letter) - 1
    
    result = 0
    for char in column_letter.upper():
        result = result * 26 + (ord(char) - ord('A') + 1)
    return result - 1

def apply_row_column_filters(df, row_range, column_range):
    """Apply row and column filters to the DataFrame."""
    if row_range:
        start_row, end_row = process_range(row_range)
        if start_row and end_row:
            start_idx = int(start_row) - 1 if start_row.isdigit() else 0
            end_idx = int(end_row) if end_row.isdigit() else len(df)
            df = df.iloc[start_idx:end_idx]
    
    if column_range:
        start_col, end_col = process_range(column_range)
        if start_col and end_col:
            start_idx = convert_column_letter_to_index(start_col) if not start_col.isdigit() else int(start_col) - 1
            end_idx = convert_column_letter_to_index(end_col) + 1 if not end_col.isdigit() else int(end_col)
            df = df.iloc[:, start_idx:end_idx]
    
    return df

def apply_query(df, query):
    """Apply a SQL-like query to filter data."""
    if not query:
        return df
    
    try:
        return df.query(query)
    except Exception as e:
        print(f"Error applying query: {e}")
        return df

def save_dataframe(df, output_path, format_type):
    """Save DataFrame to the specified format."""
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    if format_type == 'csv':
        df.to_csv(f"{output_path}.csv", index=False)
    elif format_type == 'json':
        df.to_json(f"{output_path}.json", orient='records', indent=2)
    elif format_type == 'xlsx':
        df.to_excel(f"{output_path}.xlsx", index=False)
    elif format_type == 'txt':
        df.to_csv(f"{output_path}.txt", sep='\t', index=False)

def display_excel_info(file_path):
    """Display information about the Excel file using pandas."""
    try:
        # Try with default engine first
        excel_file = pd.ExcelFile(file_path)
        sheet_names = excel_file.sheet_names
    except Exception:
        try:
            # Try with xlrd for older .xls files
            excel_file = pd.ExcelFile(file_path, engine='xlrd')
            sheet_names = excel_file.sheet_names
        except Exception as e:
            print(f"Error getting Excel info: {e}")
            return
            
    print(f"\nExcel File: {os.path.basename(file_path)}")
    print(f"Number of Sheets: {len(sheet_names)}")
    print("Sheets:")
    
    for i, sheet_name in enumerate(sheet_names, 1):
        # Read just the first few rows to get info
        try:
            df = pd.read_excel(excel_file, sheet_name=sheet_name, nrows=1)
            rows = pd.read_excel(excel_file, sheet_name=sheet_name).shape[0]
            cols = len(df.columns)
            headers = df.columns.tolist()
            
            print(f"  {i}. {sheet_name} - Rows: {rows}, Columns: {cols}")
            if headers:
                print(f"     Headers: {', '.join(str(h) for h in headers[:5])}{'...' if len(headers) > 5 else ''}")
        except Exception as e:
            print(f"  {i}. {sheet_name} - Error reading sheet: {e}")
    
    print()

def main():
    args = parse_arguments()
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    
    # Check file extension
    file_ext = Path(args.file).suffix.lower()
    if file_ext not in ['.xlsx', '.xlsm', '.xls', '.xltx', '.xltm']:
        print(f"Warning: '{file_ext}' may not be a supported Excel format.")
        print("Attempting to process anyway...")
    
    # Display file information if requested
    if args.info:
        display_excel_info(args.file)
        sys.exit(0)
    
    # Get sheet names
    all_sheets = get_sheet_names(args.file)
    
    if not all_sheets:
        print("No sheets found in the Excel file.")
        sys.exit(1)
        
    sheets_to_process = args.sheets if args.sheets else all_sheets
    
    # Validate sheet names
    valid_sheets = []
    for sheet in sheets_to_process:
        if sheet in all_sheets:
            valid_sheets.append(sheet)
        else:
            print(f"Warning: Sheet '{sheet}' not found in the Excel file.")
    
    if not valid_sheets:
        print("No valid sheets to process.")
        sys.exit(1)
    
    sheets_to_process = valid_sheets
    
    if args.verbose:
        print(f"Processing file: {args.file}")
        print(f"Sheets to process: {', '.join(sheets_to_process)}")
    
    # Determine engine based on file extension
    engine = 'openpyxl'  # Default for .xlsx, .xlsm
    if file_ext == '.xls':
        engine = 'xlrd'
    
    # Process each sheet
    all_data = []
    for sheet_name in sheets_to_process:
        if args.verbose:
            print(f"Processing sheet: {sheet_name}")
        
        # Read data
        try:
            df = pd.read_excel(args.file, sheet_name=sheet_name, engine=engine)
        except Exception as e:
            print(f"Error reading sheet '{sheet_name}': {e}")
            print("Trying alternate engine...")
            try:
                # Try alternate engine
                alt_engine = 'xlrd' if engine == 'openpyxl' else 'openpyxl'
                df = pd.read_excel(args.file, sheet_name=sheet_name, engine=alt_engine)
            except Exception as e2:
                print(f"Failed with alternate engine: {e2}")
                print(f"Skipping sheet '{sheet_name}'")
                continue
        
        # Apply filters
        df = apply_row_column_filters(df, args.rows, args.columns)
        df = apply_query(df, args.query)
        
        # Add sheet name as a column if merging
        if args.merge:
            df['sheet_name'] = sheet_name
            all_data.append(df)
        else:
            # Save individual sheet
            if '.' in os.path.basename(args.output):
                output_path = f"{os.path.splitext(args.output)[0]}_{sheet_name}"
            else:
                output_path = os.path.join(args.output, sheet_name)
            
            save_dataframe(df, output_path, args.format)
            
            if args.verbose:
                print(f"Saved sheet '{sheet_name}' to {output_path}.{args.format}")
    
    # Save merged data if requested
    if args.merge and all_data:
        merged_df = pd.concat(all_data, ignore_index=True)
        save_dataframe(merged_df, args.output, args.format)
        
        if args.verbose:
            print(f"Saved merged data to {args.output}.{args.format}")

if __name__ == "__main__":
    main()
