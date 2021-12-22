module cryptoanalysis::cc::JSONParser

import lang::json::\syntax::JSON;
import lang::json::ast::Implode;


import List; 
import String; 

import cryptoanalysis::Report; 

import ParseTree;

public AnalysisResult parseAnalysisResult(loc path) {
  JSONText json = parseJSONFile(path);
  
  AnalysisResult res = [];
  
  top-down visit(json) {
     case (Member)`"results" : [ <{ Value ","}* values> ]`: res = parseResults(values);
  }
  return res; 
}

private AnalysisResult parseResults({ Value ","}* values) {
  AnalysisResult res = []; 
  
  int startLine     = -1; 
  str cName         = ""; 
  str mName         = ""; 
  str ruleId        = ""; 
  str text          = ""; 
  str richText      = ""; 
  
  for(v <- values) {
     top-down visit(v) {
       case (Member)`"startLine" : <Value literal>` : startLine = toInt(unparse(literal)); 
       case (Member)`"ruleId" : <StringLiteral literal>` : ruleId = unparseLiteralString(literal); 
       case (Member)`"text" : <StringLiteral literal>` : text = unparseLiteralString(literal); 
       case (Member)`"richText" : <StringLiteral literal>` : richText = unparseLiteralString(literal); 
       case (Member)`"fullyQualifiedLogicalName" : <StringLiteral literal>` : {
         cName  = className(unparseLiteralString(literal));  
         mName = methodName(unparseLiteralString(literal));  
       }
     }
     res = warning(cName, mName, startLine, ruleId, [richText, text]) + res; 
  }
  
  return res; 
}

private JSONText parseJSONFile(loc path) = parse(#JSONText, path); 

private str unparseLiteralString(StringLiteral s) = replaceAll(unparse(s), "\"", ""); 

private str className(str logicalName) = intercalate(".", reverse(tail(reverse(split("::", logicalName)))));

private str methodName(str logicalName) = last(split("::", logicalName));

