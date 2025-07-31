import unittest
from yara_interpreter import *

class TestLexer(unittest.TestCase):

    def test_lexer_blank(self):
        lexer = Lexer("")
        tokens = lexer.tokenize()
        self.assertEqual(tokens, [Token(TokenType.EOF, '')])

    def test_lexer_number(self):
        lexer = Lexer("42")
        tokens = lexer.tokenize()
        self.assertEqual(tokens, [Token(TokenType.NUMBER, "42"), Token(TokenType.EOF, '')])

    def test_lexer_number_2(self):
        lexer = Lexer("42.3")
        tokens = lexer.tokenize()
        self.assertEqual(tokens, [Token(TokenType.NUMBER, "42.3"), Token(TokenType.EOF, '')])

    def test_lexer_number_3(self):
        lexer = Lexer("-42")
        tokens = lexer.tokenize()
        self.assertEqual(tokens, [Token(TokenType.MINUS, '-'), Token(TokenType.NUMBER, "42"), Token(TokenType.EOF, '')])

    def test_lexer_number_4(self):
        lexer = Lexer("-42.3")
        tokens = lexer.tokenize()
        self.assertEqual(tokens, [Token(TokenType.MINUS, '-'), Token(TokenType.NUMBER, "42.3"), Token(TokenType.EOF, '')])

if __name__ == '__main__':
    unittest.main()