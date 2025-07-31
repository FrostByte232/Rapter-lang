import basic
import sys
import os

def run_file(filename):
    try:
        with open(filename, 'r') as f:
            script = f.read()
        
        result, error = basic.run(filename, script)
        
        if error:
            print(error.as_string())
            os._exit(1)
        elif result:
            # Only print if it's not a list of null values or an empty list
            if isinstance(result, basic.List):
                # Don't print the result list for multi-statement programs
                # The individual statements (like say()) already handle their own output
                pass
            elif result != basic.Number.null:
                print(repr(result))
    except Exception as e:
        print(f"Error executing file: {str(e)}")
        os._exit(1)

def main():
    if len(sys.argv) == 2:
        # Run .rapt file
        if sys.argv[1].endswith('.rapt'):
            run_file(sys.argv[1])
        else:
            print("Error: File must have .rapt extension")
    elif len(sys.argv) > 2:
        print("Usage: shell.py [script.rapt]")
        os._exit(1)
    else:
        # Start interactive shell
        while True:
            text = input('basic > ')
            if text.strip() == "": continue
            
            result, error = basic.run('<stdin>', text)
            
            if error: 
                print(error.as_string())
            elif result and result != basic.Number.null:
                # In interactive mode, show non-null results
                if not isinstance(result, basic.List) or any(x != basic.Number.null for x in result.elements):
                    print(repr(result))

if __name__ == "__main__":
    main()