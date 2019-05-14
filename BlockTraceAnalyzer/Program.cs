using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using DotNetGraph;

namespace BlockTraceAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
             * This program gets 2 inputs:
             * List of all functions in cleaned format from IDA Pro as a list:
             * <function_name> <address> <length>
             *
             * And trace block information in cleaned format from DynamoRIO block tracking tool "drcov":
             * <block_adress>
             *
             * No other input is neccesary.
             *
             * Program outputs a graph in .dot format to be used with any GraphViz visualizer.
             *
             * There is sample input and output included in this repository.
             *
             * All numbers are in base 16. Detailed information about this algorithm can be found in the masters thesis:
             * MACHINE CODE INSTRUMENTATION FOR BLOCK RUNTIME STATISTICAL ANALYSIS AND PREDICTION
             */
            
            // Input
            const string FUNCTION_LIST_INPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\fun_list_all.txt";
            const string TRACED_BLOCKS_INPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\doc_cleaned.log";

            // Input seperator for function data columns <function_name>_SEPERATOR_<address>_SEPERATOR_<length>
            const string FUNCTION_SEPERATOR = "_SEPERATOR_";

            // Output
            const string NODE_STATS_OUTPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\node_stats.txt";
            const string GRAPH_OUTPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\graph.dot";
            const string TABLE_OUTPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\node_table.txt";
            const string NODE_LIST_OUTPUT_PATH = @"C:\Users\edza\Desktop\mag\case_study_big\node_sequence.txt";

            // We want to create a list of all functions with their beginning and end adresses
            List<string> functionsAsText = File.ReadAllText(FUNCTION_LIST_INPUT_PATH)
                .Split('\n')
                .Select(l => l.Trim())
                .ToList();

            var functionTextPattern = new Regex($"([^\\s]+){FUNCTION_SEPERATOR}([^\\s]+){FUNCTION_SEPERATOR}([^\\s]+)");
            List<MachineCodeFunction> functions = new List<MachineCodeFunction>();
            foreach (string functionTextLine in functionsAsText)
            {
                var match = functionTextPattern.Match(functionTextLine);

                functions.Add(new MachineCodeFunction()
                {
                    Name = match.Groups[1].Value,
                    Start = Convert.ToInt64(match.Groups[2].Value, 16),
                    End = Convert.ToInt64(match.Groups[2].Value, 16) + Convert.ToInt64(match.Groups[3].Value, 16),
                });
                
            }

            // We know have a block trace, for each block we figure out which function that is and replace it with a function
            List<string> linesBlocks = File.ReadAllText(TRACED_BLOCKS_INPUT_PATH)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .ToList();

            List<MachineCodeFunction> functionSequence = new List<MachineCodeFunction>();

            foreach (string block in linesBlocks)
            {
                long address = Convert.ToInt64(block, 16);

                foreach (MachineCodeFunction idaFun in functions)
                {
                    if (address >= idaFun.Start && address <= idaFun.End)
                    {
                        functionSequence.Add(idaFun);
                        break;
                    }
                }
            }

            // Add start and end
            functionSequence = functionSequence.Prepend(new MachineCodeFunction(customShortName: "Start")
            {
                Name = "Start",
            }).ToList();

            functionSequence = functionSequence.Append(new MachineCodeFunction(customShortName: "Exit")
            {
                Name = "Exit",
            }).ToList();

            // Now we reduce the function trace list by removing repeating blocks within the same func (eg. A A A B B C A A -> A B C A)
            List<MachineCodeFunction> functionListBlocksJoined = new List<MachineCodeFunction>();
            foreach (var function in functionSequence)
            {
                if (functionListBlocksJoined.Count == 0 || functionListBlocksJoined.Last() != function)
                    functionListBlocksJoined.Add(function);
            }

            string outputNodeSeq = string.Empty;
            foreach (var function in functionListBlocksJoined)
            {
                outputNodeSeq += function.ShortName + Environment.NewLine;
            }

            File.WriteAllText(NODE_LIST_OUTPUT_PATH, outputNodeSeq);

            string nodeStats = string.Empty;

            // We also calculate how often each function is called and store that as extra info
            functionListBlocksJoined.GroupBy(fun => fun)
                .ToList()
                .ForEach(functionCalls =>
                {
                    var info = functionCalls.First();
                    info.Calls = functionCalls.Count();
                    nodeStats += $"Node nr. {info.ShortName} ({info.Name}), called count: {info.Calls}\r\n";
                });

            // Then calculate avarage and stdev, if it's more than 1 stdev color change, 2 stdev extra color change
            var uniqueFunctions = functionListBlocksJoined.Distinct().ToList();
            (double stdev, double avarage) = GetStandardDeviation(uniqueFunctions.Select(node => (double)node.Calls).ToList());

            nodeStats = $"Avarage calls: {avarage}, standard deviation: {stdev}\r\n" + nodeStats;

            foreach (var function in uniqueFunctions)
            {
                if (function.Calls > avarage + 2 * stdev)
                {
                    function.NodeColor = DotColor.Green4;
                    nodeStats += $"Node nr. {function.ShortName} ({function.Name}), is called 2 STDEV more than AVG.\r\n";
                }
                else if (function.Calls > avarage + 1 * stdev)
                {
                    function.NodeColor = DotColor.Olivedrab;
                    nodeStats += $"Node nr. {function.ShortName} ({function.Name}), is called 1 STDEV more than AVG.\r\n";
                }
                else if (function.Calls < avarage - 2 * stdev)
                {
                    function.NodeColor = DotColor.Red1;
                    nodeStats += $"Node nr. {function.ShortName} ({function.Name}), is called 2 STDEV less than AVG.\r\n";
                }
                else if (function.Calls < avarage - 1 * stdev)
                {
                    function.NodeColor = DotColor.Red4;
                    nodeStats += $"Node nr. {function.ShortName} ({function.Name}), is called 1 STDEV less than AVG.\r\n";
                }
            }

            File.WriteAllText(NODE_STATS_OUTPUT_PATH, nodeStats);

            // For each node calculate all its successors for table visualization
            for (int i = 0; i < functionListBlocksJoined.Count; i++)
            {
                var @this = functionListBlocksJoined[i];

                if (i + 1 != functionListBlocksJoined.Count)
                {
                    @this.Next.Add(functionListBlocksJoined[i + 1]);
                }
            }

            string outputTable = string.Empty;

            var uniqueFunctionsNoRepeatingBlocks = functionListBlocksJoined.Distinct();

            List<(MachineCodeFunction, List<MachineCodeFunctionGrouping>)> graphAsTable = new List<(MachineCodeFunction, List<MachineCodeFunctionGrouping>)> ();

            foreach (var function in uniqueFunctionsNoRepeatingBlocks)
            {
                List<MachineCodeFunctionGrouping> tableEntry = function.Next.GroupBy(
                    functionNext => functionNext,
                    functionNext => functionNext,
                    (key, grouping) => new MachineCodeFunctionGrouping
                    {
                        ShortName = key.ShortName,
                        PreviousElement = function.ShortName,
                        NodeColor = function.NodeColor,
                        Key = key,
                        Probability = grouping.Count() / (double)function.Next.Count
                    }).ToList();

                outputTable += function.ShortName + Environment.NewLine;
                 
                foreach (var group in tableEntry)
                {
                    outputTable += group.ShortName + $" {Math.Round(group.Probability, 2)} ";
                }

                outputTable += Environment.NewLine;

                graphAsTable.Add((function, tableEntry));
            }

            File.WriteAllText(TABLE_OUTPUT_PATH, outputTable);

            // GraphViz export

            var directedGraph = new DotGraph("BlockTraceGraph", true);

            foreach (var (node, _) in graphAsTable)
            {
                var graphNode = new DotNode(node.ShortName)
                {
                    Shape = DotNodeShape.Ellipse,
                    Label = node.ShortName + $"({node.Calls})",
                    // FillColor = node.NodeColor != null ? DotColor.Grey100 : DotColor.White,
                    FontColor = node.NodeColor ?? DotColor.Black,
                    Style = (node.NodeColor != null ? DotNodeStyle.Bold : DotNodeStyle.Default),
                    Height = 0.5f,
                };

                directedGraph.Add(graphNode);
            }

            foreach (var (_, edges) in graphAsTable)
            {
                // Let's do some coloring
                // If all edges have the same weights color blue
                // If there is one and ONLY one that is higher prob than everyone then GREEN
                // if there is one and ONLY one that is higher prob than everyone then RED
                // If only GREY

                bool areAllSameProbability = edges.All(e => e.Probability == edges[0].Probability);

                if (!areAllSameProbability)
                {
                    var maxProbability = edges.Max(e => e.Probability);
                    var isOnly = edges.Count(e => e.Probability == maxProbability) == 1;
                    if (isOnly)
                    {
                        edges.First(e => e.Probability == maxProbability).Color = DotColor.Green3;
                    }

                    var minProbability = edges.Min(e => e.Probability);
                    var isOnlyMin = edges.Count(e => e.Probability == minProbability) == 1;
                    if (isOnlyMin)
                    {
                        edges.First(e => e.Probability == minProbability).Color = DotColor.Red1;
                    }
                }

                foreach (var edge in edges)
                {

                    var arrow = new DotArrow(edge.PreviousElement, edge.ShortName)
                    {
                        ArrowLabel = Math.Round(edge.Probability, 2).ToString()
                    };

                    if (areAllSameProbability)
                    {
                        arrow.ArrowColor = DotColor.Blue;
                    }

                    if (edge.Color != null)
                    {
                        arrow.ArrowColor = edge.Color.Value;
                    }

                    if (edges.Count == 1)
                    {
                        arrow.ArrowColor = DotColor.Gray;
                    }

                    directedGraph.Add(arrow);
                 }
            }

            // Indented version
            var dot = directedGraph.Compile(false);

            // Save it to a file
            File.WriteAllText(GRAPH_OUTPUT_PATH, dot);
        }

        static (double stdev, double avarage) GetStandardDeviation(List<double> list)
        {
            double average = list.Average();
            double sumOfDerivation = 0;
            foreach (double value in list)
            {
                sumOfDerivation += (value) * (value);
            }
            double sumOfDerivationAverage = sumOfDerivation / (list.Count - 1);
            return (Math.Sqrt(sumOfDerivationAverage - (average * average)), average);
        }

        class MachineCodeFunction
        {
            static int _globalCounter = 1;

            public MachineCodeFunction(string customShortName = null)
            {
                if(customShortName == null)
                {
                    this.ShortName = _globalCounter++.ToString();
                }
                else
                {
                    this.ShortName = customShortName;
                }
            }

            public string ShortName { get; private set; }
            public string Name { get; set; }
            public long Start { get; set; }
            public long End { get; set; }

            public List<MachineCodeFunction> Next { get; set; } = new List<MachineCodeFunction>();
            public int Calls { get; set; }
            public DotColor? NodeColor { get; set; }
        }

        class MachineCodeFunctionGrouping
        {
            public string ShortName { get; set; }
            public string PreviousElement { get; set; }
            public MachineCodeFunction Key { get; set; }
            public double Probability { get; set; }
            public DotColor? Color { get; set; } = null;
            public DotColor? NodeColor { get; set; }
        }
    }
}
