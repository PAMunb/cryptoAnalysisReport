module cryptoanalysis::Main

import cryptoanalysis::Report; 
import cryptoanalysis::cc::JSONParser;
import cryptoanalysis::util::IOUtil; 
import cryptoanalysis::java::Syntax; 

import ParseTree;

import IO;
import String; 
import List; 

public void main(loc csvFile) {

	list[str] content = readFileLines(csvFile);
	
	for(str s <- content) {
	   list[str] def = split(",", s); 
	   
	   assert size(def) == 4 : " Invalid csv file"; 
	   
	   str toolName    = def[0];
	   str projectName = def[1]; 
	   loc srcDir      = |file:///| + def[2]; 
	   loc jsonFile    = |file:///| + def[3];
	   
	   println("[INFO] processing <projectName> at <srcDir>");
	   
	   main(toolName, projectName, srcDir, jsonFile);
	}

}

public void main(str toolName, str projectName, loc srcDir, loc jsonFile) {
	
	AnalysisResult warnings = parseAnalysisResult(jsonFile);
	
	list[str] classNames = []; 
	
	for(Warning w <- warnings) {
	   classNames = w.className + classNames; 
	} 
	
	map[str, map[str, MethodDeclaration]] ct = buildClassTable(srcDir, classNames); 
	
		
	createGists(toolName, projectName, ct, warnings); 
} 

private void createGists(str toolName, str projectName, map[str, map[str, MethodDeclaration]] ct, AnalysisResult warnings) {

	int count = 0; 
	

	for(Warning w <- warnings) {
	    count = count + 1;
	    str m = findMethodBody(w.className, w.methodName, ct); 
	    
		str gist = 
		  "### <toolName> (report <count>) for <projectName>
		  '
		  '   * Class: <w.className>
		  '   * Method: <w.methodName> 
		  '   * Line: <w.lineNumber>
		  '   * Issue details: <w.ruleId> 
		  '<for(str message <- w.body) {>
          '      * <message>
          '<}> 
          '
          '#### Code 
          '<if(!isEmpty(m)){>
          '<m>
          '<} else {>
          '   * Not available (the binary might have been obfuscated or have been written in Kotlin. Perhaps it resides in an external library). 
          '<}>
          '
          '#### Questions
          '
          '1. How likely might this warning reveal a security threat to this app?
          '
          '2. Are you likely to accept a patch that fixes this particular issue?
          '
		  ";   
		 exportGist(projectName, gist, count, !isEmpty(m));  
	} 
	
}

private void exportGist(str projectName, str gist, int id, bool hasCode) {
   loc outDir = |project://CryptoAnalysis/out/| + projectName; 
   
   if(!exists(outDir)) {
      mkDirectory(outDir); 
   }
   loc outFile = outDir;
   if(hasCode) {
     outFile = outFile + "/gist-<id>__code.md"; 
   }
   else {
   	 outFile = outFile + "gist-<id>__noCode.md"; 
   }
   writeFile(outFile, gist);
} 

private str findMethodBody(str className, str methodName, map[str, map[str, MethodDeclaration]] ct) {
  
  if(className in ct && methodName in ct[className]) {
  	 return "```java 
  	        ' <unparse(ct[className][methodName])>
  	        '```";
  } 
  
  return ""; 
}

private map[str, map[str, MethodDeclaration]] buildClassTable(loc srcDir, list[str] classNames) {
    if(! exists(srcDir)) {
      println("[ERROR] Directory <srcDir> does not exist");
      return (); 
    } 
    
	list[loc] javaFiles = findAllFiles(srcDir, "java"); 
	
	str packageName = ""; 
	str className   = ""; 
	
	map[str, map[str, MethodDeclaration]] ct = ();
	
	int success = 0; 
	int errors = 0; 
	
	for(loc javaFile <- javaFiles) { 
	   try {
	       CompilationUnit unit = parse(#CompilationUnit, javaFile); 
	       
	       top-down visit(unit) {
	          case (PackageDeclaration)`<PackageModifier* _> package <{Identifier "."}+ name> ;` : packageName = unparse(name); 
	          case (TypeDeclaration)`<ClassModifier* _> class <Identifier name> <TypeParameters? _> <Superclass? _> <Superinterfaces? _> <ClassBody body>` : { 
	            if(className in classNames) {
	              className = packageName + "." + unparse(name);
	              ct = (className : collectMethodDeclarations(body)) + ct;
	            }  
	          } // so, we are ignoring constructors and default methods. 
	       }
	       success = success + 1; 
       }
       catch: errors = errors + 1;  
	}
	
	println("[INFO] parsed files: <success>"); 
	println("[INFO] files with errors: <errors>");
	
	return ct;
}

private map[str, MethodDeclaration] collectMethodDeclarations(ClassBody body) {
   map[str, MethodDeclaration] methods = (); 
   
   top-down visit(body) {
   	  case (MethodDeclaration)`<MethodModifier* modifiers> <MethodHeader header> <MethodBody body>`: {
   	  	 MethodDeclaration method = (MethodDeclaration)`<MethodModifier* modifiers> <MethodHeader header> <MethodBody body>`; 
   	  	 str name = findName(header); 
   	  	 methods = (name : method) + methods; 
   	  }
   }
   
   return methods; 
}

private str findName(MethodHeader header) {
   str name = ""; 
   
   top-down visit(header) {
     case (MethodDeclarator)`<Identifier n> <Formals _> <Dims? _>` :  name = unparse(n);
   }
   
   return name; 
}
 
