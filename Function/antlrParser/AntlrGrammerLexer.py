# Generated from AntlrGrammer.g4 by ANTLR 4.7.1
from antlr4 import *
from io import StringIO
from typing.io import TextIO
import sys


def serializedATN():
    with StringIO() as buf:
        buf.write("\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\t")
        buf.write("+\b\1\4\2\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7")
        buf.write("\4\b\t\b\3\2\3\2\3\3\3\3\3\4\3\4\3\4\3\4\3\5\3\5\3\5\3")
        buf.write("\6\3\6\3\6\3\6\3\7\3\7\7\7#\n\7\f\7\16\7&\13\7\3\b\3\b")
        buf.write("\3\b\3\b\2\2\t\3\3\5\4\7\5\t\6\13\7\r\b\17\t\3\2\5\5\2")
        buf.write("C\\aac|\6\2\62;C\\aac|\5\2\f\f\17\17\"\"\2+\2\3\3\2\2")
        buf.write("\2\2\5\3\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2")
        buf.write("\r\3\2\2\2\2\17\3\2\2\2\3\21\3\2\2\2\5\23\3\2\2\2\7\25")
        buf.write("\3\2\2\2\t\31\3\2\2\2\13\34\3\2\2\2\r \3\2\2\2\17\'\3")
        buf.write("\2\2\2\21\22\7*\2\2\22\4\3\2\2\2\23\24\7+\2\2\24\6\3\2")
        buf.write("\2\2\25\26\7C\2\2\26\27\7P\2\2\27\30\7F\2\2\30\b\3\2\2")
        buf.write("\2\31\32\7Q\2\2\32\33\7T\2\2\33\n\3\2\2\2\34\35\7P\2\2")
        buf.write("\35\36\7Q\2\2\36\37\7V\2\2\37\f\3\2\2\2 $\t\2\2\2!#\t")
        buf.write("\3\2\2\"!\3\2\2\2#&\3\2\2\2$\"\3\2\2\2$%\3\2\2\2%\16\3")
        buf.write("\2\2\2&$\3\2\2\2\'(\t\4\2\2()\3\2\2\2)*\b\b\2\2*\20\3")
        buf.write("\2\2\2\4\2$\3\2\3\2")
        return buf.getvalue()


class AntlrGrammerLexer(Lexer):

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    LPAREN = 1
    RPAREN = 2
    AND = 3
    OR = 4
    NOT = 5
    NAME = 6
    WS = 7

    channelNames = [ u"DEFAULT_TOKEN_CHANNEL", u"HIDDEN" ]

    modeNames = [ "DEFAULT_MODE" ]

    literalNames = [ "<INVALID>",
            "'('", "')'", "'AND'", "'OR'", "'NOT'" ]

    symbolicNames = [ "<INVALID>",
            "LPAREN", "RPAREN", "AND", "OR", "NOT", "NAME", "WS" ]

    ruleNames = [ "LPAREN", "RPAREN", "AND", "OR", "NOT", "NAME", "WS" ]

    grammarFileName = "AntlrGrammer.g4"

    def __init__(self, input=None, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.7.1")
        self._interp = LexerATNSimulator(self, self.atn, self.decisionsToDFA, PredictionContextCache())
        self._actions = None
        self._predicates = None


