##BlockTraceAnalyzer

**This program gets 2 inputs:

List of all functions in cleaned format from IDA Pro as a list:

<function_name> <address> <length>

And trace block information in cleaned format from DynamoRIO block tracking tool "drcov":

<block_adress>

No other input is neccesary.

---------------------------------

**Program outputs a graph in .dot format to be used with any GraphViz visualizer.

----------------------

**There is sample input and output included in this repository EXAMPLES folder.**

All numbers are in base 16. Detailed information about this algorithm can be found in the masters thesis:
*MACHINE CODE INSTRUMENTATION FOR BLOCK RUNTIME STATISTICAL ANALYSIS AND PREDICTION*
