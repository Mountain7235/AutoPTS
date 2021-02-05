





# Generated from AntlrGrammer.g4 by ANTLR 4.7.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .AntlrGrammerParser import AntlrGrammerParser
else:
    from AntlrGrammerParser import AntlrGrammerParser

# This class defines a complete generic visitor for a parse tree produced by AntlrGrammerParser.

class AntlrGrammerVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by AntlrGrammerParser#prog.
    def visitProg(self, ctx:AntlrGrammerParser.ProgContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#negative.
    def visitNegative(self, ctx:AntlrGrammerParser.NegativeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#Or.
    def visitOr(self, ctx:AntlrGrammerParser.OrContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#And.
    def visitAnd(self, ctx:AntlrGrammerParser.AndContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#atomExpr.
    def visitAtomExpr(self, ctx:AntlrGrammerParser.AtomExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#parens.
    def visitParens(self, ctx:AntlrGrammerParser.ParensContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by AntlrGrammerParser#name.
    def visitName(self, ctx:AntlrGrammerParser.NameContext):
        return self.visitChildren(ctx)



del AntlrGrammerParser



