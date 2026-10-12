
# LogLens Performance Note

## Current Processing Method
LogLens parses uploaded log files line by line using a Python generator. This avoids loading the entire raw log as one large text string.

However, the current dashboard stores all parsed records in a list and a Pandas DataFrame. Therefore, memory usage can still increase significantly for large files.

## Planned Optimization
For large logs, the application should process records in chunks, detect suspicious requests in each chunk, and maintain running statistics. Results should be stored incrementally instead of keeping every record in memory.

## Testing Plan
Test the application with small, medium, and large log files. Record processing time, peak memory usage, valid records processed, and suspicious requests detected.

Support for 500 MB log files must be confirmed through performance testing before it is claimed.
