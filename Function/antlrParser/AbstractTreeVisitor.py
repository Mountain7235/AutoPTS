from .AntlrGrammerVisitor import AntlrGrammerVisitor
from .AntlrGrammerParser import AntlrGrammerParser


class AbstractTreeVisitor(AntlrGrammerVisitor):

    ############################################################   
    ############################################################
    def __init__(self, dicPics):
           self.dicPics = dicPics.copy()

    ############################################################   
    ############################################################
    def visitAnd(self, ctx:AntlrGrammerParser.NameContext):
        left = self.visit(ctx.expr(0))
        right = self.visit(ctx.expr(1))
        return (left and right)

    ############################################################   
    ############################################################
    def visitOr(self, ctx:AntlrGrammerParser.NameContext):
        left = self.visit(ctx.expr(0))
        right = self.visit(ctx.expr(1))
        return (left or right)

    ############################################################   
    ############################################################
    def visitParens(self, ctx:AntlrGrammerParser.NameContext):
        return self.visit(ctx.expr())

    ############################################################   
    ############################################################
    def visitNegative(self, ctx:AntlrGrammerParser.NameContext):
        return (not self.visit(ctx.expr()))

    ############################################################   
    ############################################################
    def visitName(self, ctx:AntlrGrammerParser.NameContext):
        text = ctx.getText()
        if (text.lower().strip() == 'false'):
            return False
        elif (text.lower().strip() == 'true'):
            return True
         
        # handle the general case
        if (text.upper() in self.dicPics):
            ics = self.dicPics[text.upper()]
            return ics.lower() == 'true'
        else:
            print("Key : " + text + " is missing in the pics")
            return True

    