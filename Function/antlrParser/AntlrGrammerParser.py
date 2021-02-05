# Generated from AntlrGrammer.g4 by ANTLR 4.7.1
# encoding: utf-8
from antlr4 import *
from io import StringIO
from typing.io import TextIO
import sys

def serializedATN():
    with StringIO() as buf:
        buf.write("\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3\t")
        buf.write("\'\4\2\t\2\4\3\t\3\4\4\t\4\3\2\7\2\n\n\2\f\2\16\2\r\13")
        buf.write("\2\3\3\3\3\3\3\3\3\5\3\23\n\3\3\3\3\3\3\3\3\3\3\3\3\3")
        buf.write("\7\3\33\n\3\f\3\16\3\36\13\3\3\4\3\4\3\4\3\4\3\4\5\4%")
        buf.write("\n\4\3\4\2\3\4\5\2\4\6\2\2\2(\2\13\3\2\2\2\4\22\3\2\2")
        buf.write("\2\6$\3\2\2\2\b\n\5\4\3\2\t\b\3\2\2\2\n\r\3\2\2\2\13\t")
        buf.write("\3\2\2\2\13\f\3\2\2\2\f\3\3\2\2\2\r\13\3\2\2\2\16\17\b")
        buf.write("\3\1\2\17\20\7\7\2\2\20\23\5\4\3\6\21\23\5\6\4\2\22\16")
        buf.write("\3\2\2\2\22\21\3\2\2\2\23\34\3\2\2\2\24\25\f\5\2\2\25")
        buf.write("\26\7\5\2\2\26\33\5\4\3\6\27\30\f\4\2\2\30\31\7\6\2\2")
        buf.write("\31\33\5\4\3\5\32\24\3\2\2\2\32\27\3\2\2\2\33\36\3\2\2")
        buf.write("\2\34\32\3\2\2\2\34\35\3\2\2\2\35\5\3\2\2\2\36\34\3\2")
        buf.write("\2\2\37 \7\3\2\2 !\5\4\3\2!\"\7\4\2\2\"%\3\2\2\2#%\7\b")
        buf.write("\2\2$\37\3\2\2\2$#\3\2\2\2%\7\3\2\2\2\7\13\22\32\34$")
        return buf.getvalue()


class AntlrGrammerParser ( Parser ):

    grammarFileName = "AntlrGrammer.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'('", "')'", "'AND'", "'OR'", "'NOT'" ]

    symbolicNames = [ "<INVALID>", "LPAREN", "RPAREN", "AND", "OR", "NOT", 
                      "NAME", "WS" ]

    RULE_prog = 0
    RULE_expr = 1
    RULE_atom = 2

    ruleNames =  [ "prog", "expr", "atom" ]

    EOF = Token.EOF
    LPAREN=1
    RPAREN=2
    AND=3
    OR=4
    NOT=5
    NAME=6
    WS=7

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.7.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None



    class ProgContext(ParserRuleContext):

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def expr(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(AntlrGrammerParser.ExprContext)
            else:
                return self.getTypedRuleContext(AntlrGrammerParser.ExprContext,i)


        def getRuleIndex(self):
            return AntlrGrammerParser.RULE_prog

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterProg" ):
                listener.enterProg(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitProg" ):
                listener.exitProg(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitProg" ):
                return visitor.visitProg(self)
            else:
                return visitor.visitChildren(self)




    def prog(self):

        localctx = AntlrGrammerParser.ProgContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_prog)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 9
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << AntlrGrammerParser.LPAREN) | (1 << AntlrGrammerParser.NOT) | (1 << AntlrGrammerParser.NAME))) != 0):
                self.state = 6
                self.expr(0)
                self.state = 11
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class ExprContext(ParserRuleContext):

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return AntlrGrammerParser.RULE_expr

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class NegativeContext(ExprContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.ExprContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NOT(self):
            return self.getToken(AntlrGrammerParser.NOT, 0)
        def expr(self):
            return self.getTypedRuleContext(AntlrGrammerParser.ExprContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNegative" ):
                listener.enterNegative(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNegative" ):
                listener.exitNegative(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNegative" ):
                return visitor.visitNegative(self)
            else:
                return visitor.visitChildren(self)


    class OrContext(ExprContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.ExprContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def expr(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(AntlrGrammerParser.ExprContext)
            else:
                return self.getTypedRuleContext(AntlrGrammerParser.ExprContext,i)

        def OR(self):
            return self.getToken(AntlrGrammerParser.OR, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterOr" ):
                listener.enterOr(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitOr" ):
                listener.exitOr(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitOr" ):
                return visitor.visitOr(self)
            else:
                return visitor.visitChildren(self)


    class AndContext(ExprContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.ExprContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def expr(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(AntlrGrammerParser.ExprContext)
            else:
                return self.getTypedRuleContext(AntlrGrammerParser.ExprContext,i)

        def AND(self):
            return self.getToken(AntlrGrammerParser.AND, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAnd" ):
                listener.enterAnd(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAnd" ):
                listener.exitAnd(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAnd" ):
                return visitor.visitAnd(self)
            else:
                return visitor.visitChildren(self)


    class AtomExprContext(ExprContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.ExprContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def atom(self):
            return self.getTypedRuleContext(AntlrGrammerParser.AtomContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAtomExpr" ):
                listener.enterAtomExpr(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAtomExpr" ):
                listener.exitAtomExpr(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAtomExpr" ):
                return visitor.visitAtomExpr(self)
            else:
                return visitor.visitChildren(self)



    def expr(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = AntlrGrammerParser.ExprContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 2
        self.enterRecursionRule(localctx, 2, self.RULE_expr, _p)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 16
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [AntlrGrammerParser.NOT]:
                localctx = AntlrGrammerParser.NegativeContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 13
                self.match(AntlrGrammerParser.NOT)
                self.state = 14
                self.expr(4)
                pass
            elif token in [AntlrGrammerParser.LPAREN, AntlrGrammerParser.NAME]:
                localctx = AntlrGrammerParser.AtomExprContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 15
                self.atom()
                pass
            else:
                raise NoViableAltException(self)

            self._ctx.stop = self._input.LT(-1)
            self.state = 26
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,3,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 24
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,2,self._ctx)
                    if la_ == 1:
                        localctx = AntlrGrammerParser.AndContext(self, AntlrGrammerParser.ExprContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_expr)
                        self.state = 18
                        if not self.precpred(self._ctx, 3):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 3)")
                        self.state = 19
                        self.match(AntlrGrammerParser.AND)
                        self.state = 20
                        self.expr(4)
                        pass

                    elif la_ == 2:
                        localctx = AntlrGrammerParser.OrContext(self, AntlrGrammerParser.ExprContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_expr)
                        self.state = 21
                        if not self.precpred(self._ctx, 2):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 2)")
                        self.state = 22
                        self.match(AntlrGrammerParser.OR)
                        self.state = 23
                        self.expr(3)
                        pass

             
                self.state = 28
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,3,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx

    class AtomContext(ParserRuleContext):

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return AntlrGrammerParser.RULE_atom

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)



    class ParensContext(AtomContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.AtomContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def LPAREN(self):
            return self.getToken(AntlrGrammerParser.LPAREN, 0)
        def expr(self):
            return self.getTypedRuleContext(AntlrGrammerParser.ExprContext,0)

        def RPAREN(self):
            return self.getToken(AntlrGrammerParser.RPAREN, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterParens" ):
                listener.enterParens(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitParens" ):
                listener.exitParens(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitParens" ):
                return visitor.visitParens(self)
            else:
                return visitor.visitChildren(self)


    class NameContext(AtomContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a AntlrGrammerParser.AtomContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def NAME(self):
            return self.getToken(AntlrGrammerParser.NAME, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterName" ):
                listener.enterName(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitName" ):
                listener.exitName(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitName" ):
                return visitor.visitName(self)
            else:
                return visitor.visitChildren(self)



    def atom(self):

        localctx = AntlrGrammerParser.AtomContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_atom)
        try:
            self.state = 34
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [AntlrGrammerParser.LPAREN]:
                localctx = AntlrGrammerParser.ParensContext(self, localctx)
                self.enterOuterAlt(localctx, 1)
                self.state = 29
                self.match(AntlrGrammerParser.LPAREN)
                self.state = 30
                self.expr(0)
                self.state = 31
                self.match(AntlrGrammerParser.RPAREN)
                pass
            elif token in [AntlrGrammerParser.NAME]:
                localctx = AntlrGrammerParser.NameContext(self, localctx)
                self.enterOuterAlt(localctx, 2)
                self.state = 33
                self.match(AntlrGrammerParser.NAME)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx



    def sempred(self, localctx:RuleContext, ruleIndex:int, predIndex:int):
        if self._predicates == None:
            self._predicates = dict()
        self._predicates[1] = self.expr_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def expr_sempred(self, localctx:ExprContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 3)
         

            if predIndex == 1:
                return self.precpred(self._ctx, 2)
         




