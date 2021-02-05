grammar AntlrGrammer;

/*
 * Parser Rules
 */

prog: expr* ;

expr : NOT expr              #negative
     | expr AND expr         #And
     | expr OR expr          #Or
     | atom                  #atomExpr
     ;

atom : LPAREN expr RPAREN    #parens
     | NAME                  #name
     ;

/*
 * Lexer Rules
 */

LPAREN : '(' ;
RPAREN : ')' ;
AND : 'AND';
OR : 'OR';
NOT : 'NOT';
NAME :  ('a'..'z'|'A'..'Z'|'_') ('a'..'z'|'A'..'Z'|'0'..'9'|'_')*;
WS :   (' ' | '\r' | '\n') -> channel(HIDDEN);
