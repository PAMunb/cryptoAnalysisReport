@doc{

.Synopsis

Data structures for keeping track of crypto-analysis results. 

.Description

This module provides a simple representation for a crypto-analysis 
result (a warning). A warning indicates a class name, the line number, 
the ruleId and the message body. 
}

module cryptoanalysis::Report

alias AnalysisResult = list[Warning]; 

data Warning = warning(str className, str methodName, int lineNumber, str ruleId, list[str] body); 

