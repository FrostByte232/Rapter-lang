#!/usr/bin/env python3
"""
Yara Programming Language Interpreter
A comprehensive interpreter for the Yara language supporting:
- Variables and functions
- Control flow (loops, conditionals)
- Arrays and objects
- String interpolation
- Time-based operations
- Classes and inheritance
- Event handlers
- Hardware/system functions
- Plotting capabilities
"""

import re
import sys
import time
import threading
import random
import datetime
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from enum import Enum
from collections import deque
import math

class TokenType(Enum):
    # Literals
    NUMBER = "NUMBER"
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"
    
    # Keywords
    SET = "set"
    MAKE = "make"
    SHOW = "show"
    INPUT = "input"
    INPUT_STR = "inputStr"
    INPUT_NUM = "inputNum"
    IF = "if"
    ELIF = "elif"
    ELSE = "else"
    WHILE = "while"
    FOR = "for"
    IN = "in"
    RETURN = "return"
    BREAK = "break"
    CONTINUE = "continue"
    HALT = "halt"
    RECALL = "recall"
    REVIVE = "revive"
    WAIT = "wait"
    EVERY = "every"
    PLOT = "plot"
    CLASS = "class"
    EXTENDS = "extends"
    NEW = "new"
    ON = "on"
    
    # Operators
    ASSIGN = "="
    PLUS_ASSIGN = "+="
    MINUS_ASSIGN = "-="
    MULT_ASSIGN = "*="
    DIV_ASSIGN = "/="
    PLUS = "+"
    MINUS = "-"
    MULTIPLY = "*"
    DIVIDE = "/"
    EQUAL = "=="
    NOT_EQUAL = "!="
    LESS = "<"
    GREATER = ">"
    LESS_EQUAL = "<="
    GREATER_EQUAL = ">="
    AND = "&&"
    OR = "||"
    NOT = "!"
    INCREMENT = "++"
    DECREMENT = "--"
    
    # Punctuation
    SEMICOLON = ";"
    COMMA = ","
    DOT = "."
    COLON = ":"
    LPAREN = "("
    RPAREN = ")"
    LBRACE = "{"
    RBRACE = "}"
    LBRACKET = "["
    RBRACKET = "]"
    
    # Time units
    TIME_UNIT = "TIME_UNIT"
    
    # Special
    EOF = "EOF"
    NEWLINE = "NEWLINE"

class Token:
    def __init__(self, type_: TokenType, value: str, line: int = 1, column: int = 1):
        self.type = type_
        self.value = value
        self.line = line
        self.column = column
    
    def __repr__(self):
        return f"Token({self.type}, {repr(self.value)})"
    
    def __eq__(self, other):
        return (self.type == other.type) and (self.value == other.value)

class Lexer:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens = []
        
        # Keywords mapping
        self.keywords = {
            'set': TokenType.SET,
            'make': TokenType.MAKE,
            'show': TokenType.SHOW,
            'input': TokenType.INPUT,
            'inputStr': TokenType.INPUT_STR,
            'inputNum': TokenType.INPUT_NUM,
            'if': TokenType.IF,
            'elif': TokenType.ELIF,
            'else': TokenType.ELSE,
            'while': TokenType.WHILE,
            'for': TokenType.FOR,
            'in': TokenType.IN,
            'return': TokenType.RETURN,
            'break': TokenType.BREAK,
            'continue': TokenType.CONTINUE,
            'halt': TokenType.HALT,
            'recall': TokenType.RECALL,
            'revive': TokenType.REVIVE,
            'wait': TokenType.WAIT,
            'every': TokenType.EVERY,
            'plot': TokenType.PLOT,
            'class': TokenType.CLASS,
            'extends': TokenType.EXTENDS,
            'new': TokenType.NEW,
            'on': TokenType.ON,
        }
    
    def current_char(self) -> Optional[str]:
        if self.pos >= len(self.text):
            return None
        return self.text[self.pos]
    
    def peek_char(self, offset: int = 1) -> Optional[str]:
        peek_pos = self.pos + offset
        if peek_pos >= len(self.text):
            return None
        return self.text[peek_pos]
    
    def advance(self):
        if self.pos < len(self.text) and self.text[self.pos] == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        self.pos += 1
    
    def skip_whitespace(self):
        while self.current_char() and self.current_char().isspace():
            self.advance()
    
    def skip_comment(self):
        if self.current_char() == '/' and self.peek_char() == '/':
            # Single line comment
            while self.current_char() and self.current_char() != '\n':
                self.advance()
        elif self.current_char() == '/' and self.peek_char() == '*':
            # Multi line comment
            self.advance()  # skip '/'
            self.advance()  # skip '*'
            while self.current_char():
                if self.current_char() == '*' and self.peek_char() == '/':
                    self.advance()  # skip '*'
                    self.advance()  # skip '/'
                    break
                self.advance()
    
    def read_number(self) -> str:
        result = ""
        while self.current_char() and (self.current_char().isdigit() or self.current_char() == '.'):
            result += self.current_char()
            self.advance()
        return result
    
    def read_string(self) -> str:
        """Read simple string without interpolation"""
        quote_char = self.current_char()
        self.advance()  # skip opening quote
        
        result = ""
        while self.current_char() and self.current_char() != quote_char:
            if self.current_char() == '&':
                # Handle escape sequences
                self.advance()
                if self.current_char() == 'n':
                    result += '\n'
                elif self.current_char() == 't':
                    result += '\t'
                elif self.current_char() == 'r':
                    result += '\r'
                else:
                    result += self.current_char()
                self.advance()
            else:
                result += self.current_char()
                self.advance()
        
        if self.current_char() == quote_char:
            self.advance()  # skip closing quote
        
        return result
    
    def read_interpolated_string(self) -> List:
        """Read interpolated string with :variable: syntax"""
        quote_char = self.current_char()
        self.advance()  # skip opening quote
        
        parts = []
        current_text = ""
        
        while self.current_char() and self.current_char() != quote_char:
            if self.current_char() == ':':
                # Save any accumulated text
                if current_text:
                    parts.append(('text', current_text))
                    current_text = ""
                
                self.advance()  # skip ':'
                
                # Read the expression inside :...:
                expr_text = ""
                while self.current_char() and self.current_char() != ':':
                    expr_text += self.current_char()
                    self.advance()
                
                if self.current_char() == ':':
                    self.advance()  # skip closing ':'
                    
                    # Check for update type (.live or .update)
                    update_type = None
                    if '.' in expr_text:
                        expr_parts = expr_text.split('.')
                        expr_text = expr_parts[0]
                        if len(expr_parts) > 1 and expr_parts[1] in ('live', 'update'):
                            update_type = expr_parts[1]
                    
                    parts.append(('interpolation', expr_text, update_type))
                else:
                    # No closing :, treat as regular text
                    current_text += ':' + expr_text
            
            elif self.current_char() == '&':
                # Handle escape sequences
                self.advance()
                if self.current_char() == 'n':
                    current_text += '\n'
                elif self.current_char() == 't':
                    current_text += '\t'
                elif self.current_char() == 'r':
                    current_text += '\r'
                else:
                    current_text += self.current_char()
                self.advance()
            else:
                current_text += self.current_char()
                self.advance()
        
        # Save any remaining text
        if current_text:
            parts.append(('text', current_text))
        
        if self.current_char() == quote_char:
            self.advance()  # skip closing quote
        
        return parts
    
    def read_time_unit(self) -> str:
        """Read time expressions like 1s, 2m, 1h30m15s"""
        result = ""
        
        # Read number
        while self.current_char() and self.current_char().isdigit():
            result += self.current_char()
            self.advance()
        
        # Read time suffix
        if self.current_char() and self.current_char().isalpha():
            suffix = ""
            while self.current_char() and self.current_char().isalpha():
                suffix += self.current_char()
                self.advance()
            
            if suffix in ('ms', 's', 'm', 'h'):
                result += suffix
            else:
                # Not a time unit, backtrack
                for _ in range(len(suffix)):
                    self.pos -= 1
                    self.column -= 1
        
        return result
    
    def read_identifier(self) -> str:
        result = ""
        while (self.current_char() and 
               (self.current_char().isalnum() or self.current_char() == '_')):
            result += self.current_char()
            self.advance()
        return result
    
    def tokenize(self) -> List[Token]:
        while self.current_char():
            char = self.current_char()
            
            if char.isspace():
                self.skip_whitespace()
                continue
            
            if char == '/' and (self.peek_char() == '/' or self.peek_char() == '*'):
                self.skip_comment()
                continue
            
            # Numbers (check for time units first)
            if char.isdigit():
                # Save position to potentially backtrack
                saved_pos = self.pos
                saved_line = self.line
                saved_col = self.column
                
                # Try to read as time unit first
                time_unit = self.read_time_unit()
                
                # Check if it's a valid time unit
                if len(time_unit) > 1 and (time_unit[-1:] in 'smh' or time_unit.endswith('ms')):
                    self.tokens.append(Token(TokenType.TIME_UNIT, time_unit, saved_line, saved_col))
                    continue
                else:
                    # Backtrack and read as regular number
                    self.pos = saved_pos
                    self.line = saved_line
                    self.column = saved_col
                    number = self.read_number()
                    self.tokens.append(Token(TokenType.NUMBER, number, self.line, self.column))
                    continue
            
            # Strings (check for interpolation)
            if char in ('"', "'"):
                # Peek ahead to see if there's a : indicating interpolation
                saved_pos = self.pos
                saved_line = self.line
                saved_col = self.column
                
                # Quick scan to check for interpolation
                temp_pos = self.pos + 1
                has_interpolation = False
                quote_char = char
                
                while temp_pos < len(self.text) and self.text[temp_pos] != quote_char:
                    if self.text[temp_pos] == ':':
                        has_interpolation = True
                        break
                    temp_pos += 1
                
                if has_interpolation:
                    # Parse as interpolated string
                    string_parts = self.read_interpolated_string()
                    
                    # Create InterpolatedString token with the parts
                    self.tokens.append(Token(TokenType.STRING, string_parts, saved_line, saved_col))
                else:
                    # Parse as simple string
                    string_value = self.read_string()
                    self.tokens.append(Token(TokenType.STRING, string_value, saved_line, saved_col))
                continue
            
            # Identifiers and keywords
            if char.isalpha() or char == '_':
                identifier = self.read_identifier()
                token_type = self.keywords.get(identifier, TokenType.IDENTIFIER)
                self.tokens.append(Token(token_type, identifier, self.line, self.column))
                continue
            
            # Two-character operators
            if char == '+' and self.peek_char() == '+':
                self.tokens.append(Token(TokenType.INCREMENT, "++", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '-' and self.peek_char() == '-':
                self.tokens.append(Token(TokenType.DECREMENT, "--", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '+' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.PLUS_ASSIGN, "+=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '-' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.MINUS_ASSIGN, "-=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '*' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.MULT_ASSIGN, "*=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '/' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.DIV_ASSIGN, "/=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '=' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.EQUAL, "==", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '!' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.NOT_EQUAL, "!=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '<' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.LESS_EQUAL, "<=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '>' and self.peek_char() == '=':
                self.tokens.append(Token(TokenType.GREATER_EQUAL, ">=", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '&' and self.peek_char() == '&':
                self.tokens.append(Token(TokenType.AND, "&&", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            if char == '|' and self.peek_char() == '|':
                self.tokens.append(Token(TokenType.OR, "||", self.line, self.column))
                self.advance()
                self.advance()
                continue
            
            # Single character tokens
            single_char_tokens = {
                '=': TokenType.ASSIGN,
                '+': TokenType.PLUS,
                '-': TokenType.MINUS,
                '*': TokenType.MULTIPLY,
                '/': TokenType.DIVIDE,
                '<': TokenType.LESS,
                '>': TokenType.GREATER,
                '!': TokenType.NOT,
                ';': TokenType.SEMICOLON,
                ',': TokenType.COMMA,
                '.': TokenType.DOT,
                ':': TokenType.COLON,
                '(': TokenType.LPAREN,
                ')': TokenType.RPAREN,
                '{': TokenType.LBRACE,
                '}': TokenType.RBRACE,
                '[': TokenType.LBRACKET,
                ']': TokenType.RBRACKET,
            }
            
            if char in single_char_tokens:
                self.tokens.append(Token(single_char_tokens[char], char, self.line, self.column))
                self.advance()
                continue
            
            # Unknown character
            raise SyntaxError(f"Unknown character '{char}' at line {self.line}, column {self.column}")
        
        self.tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return self.tokens

# AST Node classes
class ASTNode:
    pass

class Program(ASTNode):
    def __init__(self, statements: List[ASTNode]):
        self.statements = statements

class VarDeclaration(ASTNode):
    def __init__(self, name: str, value: ASTNode, op: str = "="):
        self.name = name
        self.value = value
        self.op = op

class ShowStatement(ASTNode):
    def __init__(self, expression: ASTNode):
        self.expression = expression

class InputStatement(ASTNode):
    def __init__(self, prompt: Optional[str] = None, input_type: str = "input"):
        self.prompt = prompt
        self.input_type = input_type

class BinaryOp(ASTNode):
    def __init__(self, left: ASTNode, op: str, right: ASTNode):
        self.left = left
        self.op = op
        self.right = right

class UnaryOp(ASTNode):
    def __init__(self, op: str, operand: ASTNode, postfix: bool = False):
        self.op = op
        self.operand = operand
        self.postfix = postfix

class Number(ASTNode):
    def __init__(self, value: float):
        self.value = value

class String(ASTNode):
    def __init__(self, value: str):
        self.value = value

class Identifier(ASTNode):
    def __init__(self, name: str):
        self.name = name

class Array(ASTNode):
    def __init__(self, elements: List[ASTNode]):
        self.elements = elements

class Object(ASTNode):
    def __init__(self, pairs: List[tuple]):  # List of (key, value) tuples
        self.pairs = pairs

class ArrayAccess(ASTNode):
    def __init__(self, array: ASTNode, index: ASTNode):
        self.array = array
        self.index = index

class PropertyAccess(ASTNode):
    def __init__(self, object: ASTNode, property: str):
        self.object = object
        self.property = property

class InterpolatedString(ASTNode):
    def __init__(self, parts: List[ASTNode]):  # Mix of strings and expressions
        self.parts = parts

class StringPart(ASTNode):
    def __init__(self, value: str):
        self.value = value

class InterpolationPart(ASTNode):
    def __init__(self, expression: ASTNode, update_type: Optional[str] = None):
        self.expression = expression
        self.update_type = update_type  # "live" or "update" or None

class WhileLoop(ASTNode):
    def __init__(self, condition: ASTNode, body: List[ASTNode]):
        self.condition = condition
        self.body = body

class ForLoop(ASTNode):
    def __init__(self, variable: str, iterable: ASTNode, body: List[ASTNode]):
        self.variable = variable
        self.iterable = iterable
        self.body = body

class IfStatement(ASTNode):
    def __init__(self, condition: ASTNode, then_stmt: ASTNode, 
                 elif_clauses: List[tuple] = None, else_stmt: ASTNode = None):
        self.condition = condition
        self.then_stmt = then_stmt
        self.elif_clauses = elif_clauses or []  # List of (condition, statement) tuples
        self.else_stmt = else_stmt

class FunctionDeclaration(ASTNode):
    def __init__(self, name: str, params: List[str], body: List[ASTNode]):
        self.name = name
        self.params = params
        self.body = body

class FunctionCall(ASTNode):
    def __init__(self, name: str, args: List[ASTNode]):
        self.name = name
        self.args = args

class ReturnStatement(ASTNode):
    def __init__(self, value: Optional[ASTNode] = None):
        self.value = value

class BreakStatement(ASTNode):
    pass

class ContinueStatement(ASTNode):
    pass

class Block(ASTNode):
    def __init__(self, statements: List[ASTNode]):
        self.statements = statements

class WaitStatement(ASTNode):
    def __init__(self, time_expr: ASTNode):
        self.time_expr = time_expr

class EveryStatement(ASTNode):
    def __init__(self, time_expr: ASTNode, statement: ASTNode):
        self.time_expr = time_expr
        self.statement = statement

class TimeExpression(ASTNode):
    def __init__(self, value: str):
        self.value = value  # e.g., "1s", "2m", "1h30m"

class HaltStatement(ASTNode):
    def __init__(self, condition: ASTNode):
        self.condition = condition

class RecallStatement(ASTNode):
    def __init__(self, identifier: str):
        self.identifier = identifier

class ReviveStatement(ASTNode):
    def __init__(self, identifier: str):
        self.identifier = identifier

class PlotStatement(ASTNode):
    def __init__(self, expression: ASTNode, options: Dict[str, ASTNode] = None):
        self.expression = expression
        self.options = options or {}

class ClassDeclaration(ASTNode):
    def __init__(self, name: str, parent: Optional[str], members: List[ASTNode]):
        self.name = name
        self.parent = parent
        self.members = members

class MethodDeclaration(ASTNode):
    def __init__(self, name: str, params: List[str], body: List[ASTNode]):
        self.name = name
        self.params = params
        self.body = body

class PropertyDeclaration(ASTNode):
    def __init__(self, name: str, value: ASTNode):
        self.name = name
        self.value = value

class NewExpression(ASTNode):
    def __init__(self, class_name: str, args: List[ASTNode]):
        self.class_name = class_name
        self.args = args

class EventHandler(ASTNode):
    def __init__(self, event_type: str, params: List[str], body: List[ASTNode]):
        self.event_type = event_type
        self.params = params
        self.body = body

class SystemFunction(ASTNode):
    def __init__(self, function_name: str, args: List[ASTNode]):
        self.function_name = function_name
        self.args = args

class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def current_token(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]  # EOF token
        return self.tokens[self.pos]
    
    def peek_token(self, offset: int = 1) -> Token:
        peek_pos = self.pos + offset
        if peek_pos >= len(self.tokens):
            return self.tokens[-1]  # EOF token
        return self.tokens[peek_pos]
    
    def advance(self):
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
    
    def expect(self, token_type: TokenType) -> Token:
        token = self.current_token()
        if token.type != token_type:
            raise SyntaxError(f"Expected {token_type}, got {token.type} at line {token.line}")
        self.advance()
        return token
    
    def parse(self) -> Program:
        statements = []
        while self.current_token().type != TokenType.EOF:
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
        return Program(statements)
    
    def parse_statement(self) -> Optional[ASTNode]:
        token = self.current_token()
        
        if token.type == TokenType.SET:
            return self.parse_var_declaration()
        elif token.type == TokenType.SHOW:
            return self.parse_show_statement()
        elif token.type in (TokenType.INPUT, TokenType.INPUT_STR, TokenType.INPUT_NUM):
            return self.parse_input_statement()
        elif token.type == TokenType.MAKE:
            return self.parse_function_declaration()
        elif token.type == TokenType.WHILE:
            return self.parse_while_loop()
        elif token.type == TokenType.FOR:
            return self.parse_for_loop()
        elif token.type == TokenType.IF:
            return self.parse_if_statement()
        elif token.type == TokenType.WAIT:
            return self.parse_wait_statement()
        elif token.type == TokenType.EVERY:
            return self.parse_every_statement()
        elif token.type == TokenType.RETURN:
            return self.parse_return_statement()
        elif token.type == TokenType.BREAK:
            self.advance()
            self.expect(TokenType.SEMICOLON)
            return BreakStatement()
        elif token.type == TokenType.CONTINUE:
            self.advance()
            self.expect(TokenType.SEMICOLON)
            return ContinueStatement()
        elif token.type == TokenType.HALT:
            return self.parse_halt_statement()
        elif token.type == TokenType.RECALL:
            return self.parse_recall_statement()
        elif token.type == TokenType.REVIVE:
            return self.parse_revive_statement()
        elif token.type == TokenType.PLOT:
            return self.parse_plot_statement()
        elif token.type == TokenType.CLASS:
            return self.parse_class_declaration()
        elif token.type == TokenType.ON:
            return self.parse_event_handler()
        elif token.type == TokenType.LBRACE:
            return self.parse_block()
        else:
            # Expression statement or unknown
            try:
                expr = self.parse_expression()
                self.expect(TokenType.SEMICOLON)
                return expr
            except:
                self.advance()
                return None
    
    def parse_var_declaration(self) -> VarDeclaration:
        self.expect(TokenType.SET)
        name = self.expect(TokenType.IDENTIFIER).value
        
        # Check for assignment operator
        op_token = self.current_token()
        if op_token.type in (TokenType.ASSIGN, TokenType.PLUS_ASSIGN, 
                           TokenType.MINUS_ASSIGN, TokenType.MULT_ASSIGN, 
                           TokenType.DIV_ASSIGN):
            op = op_token.value
            self.advance()
        else:
            raise SyntaxError(f"Expected assignment operator, got {op_token.type}")
        
        value = self.parse_expression()
        self.expect(TokenType.SEMICOLON)
        
        return VarDeclaration(name, value, op)
    
    def parse_show_statement(self) -> ShowStatement:
        self.expect(TokenType.SHOW)
        self.expect(TokenType.LPAREN)
        expr = self.parse_expression()
        self.expect(TokenType.RPAREN)
        self.expect(TokenType.SEMICOLON)
        
        return ShowStatement(expr)
    
    def parse_input_statement(self) -> InputStatement:
        input_type = self.current_token().value
        self.advance()
        self.expect(TokenType.LPAREN)
        
        prompt = None
        if self.current_token().type == TokenType.STRING:
            prompt = self.current_token().value
            self.advance()
        
        self.expect(TokenType.RPAREN)
        self.expect(TokenType.SEMICOLON)
        
        return InputStatement(prompt, input_type)
    
    def parse_function_declaration(self) -> FunctionDeclaration:
        self.expect(TokenType.MAKE)
        name = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.LPAREN)
        
        # Parse parameters
        params = []
        if self.current_token().type == TokenType.IDENTIFIER:
            params.append(self.expect(TokenType.IDENTIFIER).value)
            while self.current_token().type == TokenType.COMMA:
                self.advance()
                params.append(self.expect(TokenType.IDENTIFIER).value)
        
        self.expect(TokenType.RPAREN)
        
        # Parse function body
        if self.current_token().type == TokenType.RETURN:
            # Single expression return
            self.advance()
            expr = self.parse_expression()
            self.expect(TokenType.SEMICOLON)
            return FunctionDeclaration(name, params, [ReturnStatement(expr)])
        else:
            # Multi-statement body
            body_block = self.parse_block()
            return FunctionDeclaration(name, params, body_block.statements)
    
    def parse_while_loop(self) -> WhileLoop:
        self.expect(TokenType.WHILE)
        self.expect(TokenType.LPAREN)
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN)
        body_block = self.parse_block()
        return WhileLoop(condition, body_block.statements)
    
    def parse_for_loop(self) -> ForLoop:
        self.expect(TokenType.FOR)
        self.expect(TokenType.LPAREN)
        var_name = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.IN)
        iterable = self.parse_expression()
        self.expect(TokenType.RPAREN)
        body_block = self.parse_block()
        return ForLoop(var_name, iterable, body_block.statements)
    
    def parse_if_statement(self) -> IfStatement:
        self.expect(TokenType.IF)
        self.expect(TokenType.LPAREN)
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN)
        then_stmt = self.parse_statement()
        
        # Parse elif clauses
        elif_clauses = []
        while self.current_token().type == TokenType.ELIF:
            self.advance()
            self.expect(TokenType.LPAREN)
            elif_condition = self.parse_expression()
            self.expect(TokenType.RPAREN)
            elif_stmt = self.parse_statement()
            elif_clauses.append((elif_condition, elif_stmt))
        
        # Parse else clause
        else_stmt = None
        if self.current_token().type == TokenType.ELSE:
            self.advance()
            else_stmt = self.parse_statement()
        
        return IfStatement(condition, then_stmt, elif_clauses, else_stmt)
    
    def parse_wait_statement(self) -> WaitStatement:
        self.expect(TokenType.WAIT)
        time_expr = self.parse_time_expression()
        self.expect(TokenType.SEMICOLON)
        return WaitStatement(time_expr)
    
    def parse_every_statement(self) -> EveryStatement:
        self.expect(TokenType.EVERY)
        time_expr = self.parse_time_expression()
        statement = self.parse_statement()
        return EveryStatement(time_expr, statement)
    
    def parse_return_statement(self) -> ReturnStatement:
        self.expect(TokenType.RETURN)
        value = None
        if self.current_token().type != TokenType.SEMICOLON:
            value = self.parse_expression()
        self.expect(TokenType.SEMICOLON)
        return ReturnStatement(value)
    
    def parse_halt_statement(self) -> HaltStatement:
        self.expect(TokenType.HALT)
        self.expect(TokenType.IF)
        self.expect(TokenType.LPAREN)
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN)
        self.expect(TokenType.SEMICOLON)
        return HaltStatement(condition)
    
    def parse_recall_statement(self) -> RecallStatement:
        self.expect(TokenType.RECALL)
        identifier = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.SEMICOLON)
        return RecallStatement(identifier)
    
    def parse_revive_statement(self) -> ReviveStatement:
        self.expect(TokenType.REVIVE)
        identifier = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.SEMICOLON)
        return ReviveStatement(identifier)
    
    def parse_plot_statement(self) -> PlotStatement:
        self.expect(TokenType.PLOT)
        self.expect(TokenType.LPAREN)
        
        # Parse main expression
        expr = self.parse_expression()
        
        # Parse optional plot options
        options = {}
        if self.current_token().type == TokenType.COMMA:
            self.advance()
            # Parse options like type: "bar", color: "red"
            while self.current_token().type == TokenType.IDENTIFIER:
                key = self.current_token().value
                self.advance()
                self.expect(TokenType.COLON)
                value = self.parse_expression()
                options[key] = value
                
                if self.current_token().type == TokenType.COMMA:
                    self.advance()
                else:
                    break
        
        self.expect(TokenType.RPAREN)
        self.expect(TokenType.SEMICOLON)
        return PlotStatement(expr, options)
    
    def parse_class_declaration(self) -> ClassDeclaration:
        self.expect(TokenType.CLASS)
        name = self.expect(TokenType.IDENTIFIER).value
        
        # Check for inheritance
        parent = None
        if self.current_token().type == TokenType.EXTENDS:
            self.advance()
            parent = self.expect(TokenType.IDENTIFIER).value
        
        self.expect(TokenType.LBRACE)
        
        # Parse class members
        members = []
        while self.current_token().type != TokenType.RBRACE and self.current_token().type != TokenType.EOF:
            if self.current_token().type == TokenType.MAKE:
                # Method declaration
                self.advance()
                method_name = self.expect(TokenType.IDENTIFIER).value
                self.expect(TokenType.LPAREN)
                
                # Parse parameters
                params = []
                if self.current_token().type == TokenType.IDENTIFIER:
                    params.append(self.expect(TokenType.IDENTIFIER).value)
                    while self.current_token().type == TokenType.COMMA:
                        self.advance()
                        params.append(self.expect(TokenType.IDENTIFIER).value)
                
                self.expect(TokenType.RPAREN)
                
                # Parse method body
                if self.current_token().type == TokenType.RETURN:
                    # Single expression return
                    self.advance()
                    expr = self.parse_expression()
                    self.expect(TokenType.SEMICOLON)
                    members.append(MethodDeclaration(method_name, params, [ReturnStatement(expr)]))
                else:
                    # Multi-statement body
                    body_block = self.parse_block()
                    members.append(MethodDeclaration(method_name, params, body_block.statements))
            
            elif self.current_token().type == TokenType.SET:
                # Property declaration
                self.advance()
                prop_name = self.expect(TokenType.IDENTIFIER).value
                self.expect(TokenType.ASSIGN)
                value = self.parse_expression()
                self.expect(TokenType.SEMICOLON)
                members.append(PropertyDeclaration(prop_name, value))
            else:
                # Skip unknown tokens
                self.advance()
        
        self.expect(TokenType.RBRACE)
        return ClassDeclaration(name, parent, members)
    
    def parse_event_handler(self) -> EventHandler:
        self.expect(TokenType.ON)
        event_type = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.LPAREN)
        
        # Parse parameters
        params = []
        if self.current_token().type == TokenType.IDENTIFIER:
            params.append(self.expect(TokenType.IDENTIFIER).value)
            while self.current_token().type == TokenType.COMMA:
                self.advance()
                params.append(self.expect(TokenType.IDENTIFIER).value)
        
        self.expect(TokenType.RPAREN)
        
        # Parse body
        body_block = self.parse_block()
        return EventHandler(event_type, params, body_block.statements)
    
    def parse_block(self) -> Block:
        self.expect(TokenType.LBRACE)
        statements = []
        while self.current_token().type != TokenType.RBRACE and self.current_token().type != TokenType.EOF:
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
        self.expect(TokenType.RBRACE)
        return Block(statements)
    
    def parse_time_expression(self) -> TimeExpression:
        # Parse time expressions like 1s, 2m, 1h30m15s
        time_parts = []
        
        while self.current_token().type == TokenType.TIME_UNIT:
            time_parts.append(self.current_token().value)
            self.advance()
        
        if not time_parts:
            raise SyntaxError(f"Expected time expression at line {self.current_token().line}")
        
        return TimeExpression("".join(time_parts))
    
    def parse_interpolated_string(self, parts: List) -> InterpolatedString:
        """Parse interpolated string parts into AST nodes"""
        ast_parts = []
        
        for part in parts:
            if part[0] == 'text':
                ast_parts.append(StringPart(part[1]))
            elif part[0] == 'interpolation':
                # Parse the expression
                expr_text = part[1]
                update_type = part[2] if len(part) > 2 else None
                
                # Create a mini-lexer/parser for the expression
                expr_lexer = Lexer(expr_text)
                expr_tokens = expr_lexer.tokenize()
                expr_parser = Parser(expr_tokens)
                expr_ast = expr_parser.parse_expression()
                
                ast_parts.append(InterpolationPart(expr_ast, update_type))
        
        return InterpolatedString(ast_parts)
    
    def parse_array(self) -> Array:
        """Parse array literal [1, 2, 3]"""
        self.expect(TokenType.LBRACKET)
        elements = []
        
        if self.current_token().type != TokenType.RBRACKET:
            elements.append(self.parse_expression())
            while self.current_token().type == TokenType.COMMA:
                self.advance()
                if self.current_token().type == TokenType.RBRACKET:
                    break  # Trailing comma
                elements.append(self.parse_expression())
        
        self.expect(TokenType.RBRACKET)
        return Array(elements)
    
    def parse_object(self) -> Object:
        """Parse object literal {key: value, key2: value2}"""
        self.expect(TokenType.LBRACE)
        pairs = []
        
        if self.current_token().type != TokenType.RBRACE:
            # Parse first pair
            key = self.expect(TokenType.IDENTIFIER).value
            self.expect(TokenType.COLON)
            value = self.parse_expression()
            pairs.append((key, value))
            
            while self.current_token().type == TokenType.COMMA:
                self.advance()
                if self.current_token().type == TokenType.RBRACE:
                    break  # Trailing comma
                
                key = self.expect(TokenType.IDENTIFIER).value
                self.expect(TokenType.COLON)
                value = self.parse_expression()
                pairs.append((key, value))
        
        self.expect(TokenType.RBRACE)
        return Object(pairs)
    
    def parse_expression(self) -> ASTNode:
        return self.parse_or_expr()
    
    def parse_or_expr(self) -> ASTNode:
        node = self.parse_and_expr()
        
        while self.current_token().type == TokenType.OR:
            op = self.current_token().value
            self.advance()
            right = self.parse_and_expr()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_and_expr(self) -> ASTNode:
        node = self.parse_equality_expr()
        
        while self.current_token().type == TokenType.AND:
            op = self.current_token().value
            self.advance()
            right = self.parse_equality_expr()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_equality_expr(self) -> ASTNode:
        node = self.parse_comparison_expr()
        
        while self.current_token().type in (TokenType.EQUAL, TokenType.NOT_EQUAL):
            op = self.current_token().value
            self.advance()
            right = self.parse_comparison_expr()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_comparison_expr(self) -> ASTNode:
        node = self.parse_arithmetic_expr()
        
        while self.current_token().type in (TokenType.LESS, TokenType.GREATER,
                                          TokenType.LESS_EQUAL, TokenType.GREATER_EQUAL):
            op = self.current_token().value
            self.advance()
            right = self.parse_arithmetic_expr()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_arithmetic_expr(self) -> ASTNode:
        node = self.parse_term()
        
        while self.current_token().type in (TokenType.PLUS, TokenType.MINUS):
            op = self.current_token().value
            self.advance()
            right = self.parse_term()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_term(self) -> ASTNode:
        node = self.parse_factor()
        
        while self.current_token().type in (TokenType.MULTIPLY, TokenType.DIVIDE):
            op = self.current_token().value
            self.advance()
            right = self.parse_factor()
            node = BinaryOp(node, op, right)
        
        return node
    
    def parse_factor(self) -> ASTNode:
        token = self.current_token()
        
        if token.type in (TokenType.PLUS, TokenType.MINUS, TokenType.NOT):
            op = token.value
            self.advance()
            operand = self.parse_factor()
            return UnaryOp(op, operand)
        
        return self.parse_postfix()
    
    def parse_postfix(self) -> ASTNode:
        node = self.parse_primary()
        
        while True:
            if self.current_token().type == TokenType.INCREMENT:
                self.advance()
                node = UnaryOp("++", node, postfix=True)
            elif self.current_token().type == TokenType.DECREMENT:
                self.advance()
                node = UnaryOp("--", node, postfix=True)
            elif self.current_token().type == TokenType.LBRACKET:
                # Array access
                self.advance()
                index = self.parse_expression()
                self.expect(TokenType.RBRACKET)
                node = ArrayAccess(node, index)
            elif self.current_token().type == TokenType.DOT:
                # Property access
                self.advance()
                prop_name = self.expect(TokenType.IDENTIFIER).value
                node = PropertyAccess(node, prop_name)
            else:
                break
        
        return node
    
    def parse_primary(self) -> ASTNode:
        token = self.current_token()
        
        if token.type == TokenType.NUMBER:
            self.advance()
            return Number(float(token.value))
        
        elif token.type == TokenType.STRING:
            string_value = token.value
            self.advance()
            
            # Check if it's an interpolated string (list of parts)
            if isinstance(string_value, list):
                return self.parse_interpolated_string(string_value)
            else:
                return String(string_value)
        
        elif token.type == TokenType.LBRACKET:
            return self.parse_array()
        
        elif token.type == TokenType.LBRACE:
            return self.parse_object()
        
        elif token.type == TokenType.NEW:
            self.advance()
            class_name = self.expect(TokenType.IDENTIFIER).value
            self.expect(TokenType.LPAREN)
            
            args = []
            if self.current_token().type != TokenType.RPAREN:
                args.append(self.parse_expression())
                while self.current_token().type == TokenType.COMMA:
                    self.advance()
                    args.append(self.parse_expression())
            
            self.expect(TokenType.RPAREN)
            return NewExpression(class_name, args)
        
        elif token.type == TokenType.IDENTIFIER:
            name = token.value
            self.advance()
            
            # Check for function call or system functions
            if self.current_token().type == TokenType.LPAREN:
                # Check if it's a system function
                if name in ["getMouseClick", "getKeyPress", "readSensor", "inputReady"]:
                    self.advance()  # skip LPAREN
                    args = []
                    
                    if self.current_token().type != TokenType.RPAREN:
                        args.append(self.parse_expression())
                        while self.current_token().type == TokenType.COMMA:
                            self.advance()
                            args.append(self.parse_expression())
                    
                    self.expect(TokenType.RPAREN)
                    return SystemFunction(name, args)
                else:
                    # Regular function call
                    self.advance()  # skip LPAREN
                    args = []
                    
                    if self.current_token().type != TokenType.RPAREN:
                        args.append(self.parse_expression())
                        while self.current_token().type == TokenType.COMMA:
                            self.advance()
                            args.append(self.parse_expression())
                    
                    self.expect(TokenType.RPAREN)
                    return FunctionCall(name, args)
            
            # Check for time.now
            elif name == "time" and self.current_token().type == TokenType.DOT:
                self.advance()  # skip DOT
                if self.current_token().value == "now":
                    self.advance()
                    return SystemFunction("time.now", [])
            
            return Identifier(name)
        
        elif token.type == TokenType.LPAREN:
            self.advance()
            expr = self.parse_expression()
            self.expect(TokenType.RPAREN)
            return expr
        
        elif token.type == TokenType.TIME_UNIT:
            return self.parse_time_expression()
        
        elif token.type in (TokenType.INPUT, TokenType.INPUT_STR, TokenType.INPUT_NUM):
            # Input as expression
            input_type = token.value
            self.advance()
            self.expect(TokenType.LPAREN)
            
            prompt = None
            if self.current_token().type == TokenType.STRING:
                prompt = self.current_token().value
                self.advance()
            
            self.expect(TokenType.RPAREN)
            return FunctionCall(input_type, [String(prompt)] if prompt else [])
        
        else:
            raise SyntaxError(f"Unexpected token {token.type} at line {token.line}")

# Control flow exceptions for break/continue
class BreakException(Exception):
    pass

class ContinueException(Exception):
    pass

class ReturnException(Exception):
    def __init__(self, value=None):
        self.value = value

class HaltException(Exception):
    pass

# Simple class system
class YaraClass:
    def __init__(self, name: str, parent: Optional['YaraClass'], methods: Dict[str, MethodDeclaration], properties: Dict[str, Any]):
        self.name = name
        self.parent = parent
        self.methods = methods
        self.properties = properties

class YaraInstance:
    def __init__(self, yara_class: YaraClass):
        self.yara_class = yara_class
        self.properties = {}
        
        # Initialize properties from class
        for prop_name, prop_value in yara_class.properties.items():
            self.properties[prop_name] = prop_value
        
        # Inherit from parent
        parent = yara_class.parent
        while parent:
            for prop_name, prop_value in parent.properties.items():
                if prop_name not in self.properties:
                    self.properties[prop_name] = prop_value
            parent = parent.parent

class Interpreter:
    def __init__(self):
        self.variables: Dict[str, Any] = {}
        self.functions: Dict[str, FunctionDeclaration] = {}
        self.classes: Dict[str, YaraClass] = {}
        self.event_handlers: Dict[str, List[EventHandler]] = {}
        self.call_stack: List[Dict[str, Any]] = []
        self.every_threads: List[threading.Thread] = []
        self.live_displays: Dict[str, Any] = {}  # For live string interpolation
        self.recalled_values: Dict[str, Any] = {}  # For recall/revive functionality
        
        # Simulated hardware state
        self.mouse_clicks: deque = deque(maxlen=10)
        self.key_presses: deque = deque(maxlen=10)
        self.sensors: Dict[str, float] = {
            "temperature": 20.0,
            "humidity": 50.0,
            "light": 100.0
        }
    
    def parse_time_to_seconds(self, time_str: str) -> float:
        """Convert time string like '1h30m15s' to seconds"""
        total_seconds = 0.0
        current_number = ""
        
        i = 0
        while i < len(time_str):
            char = time_str[i]
            
            if char.isdigit():
                current_number += char
            elif char in 'smh' or (char == 's' and i > 0 and time_str[i-1] == 'm'):
                if current_number:
                    num = float(current_number)
                    
                    # Handle 'ms' case
                    if char == 's' and i > 0 and time_str[i-1] == 'm':
                        total_seconds += num / 1000  # milliseconds
                        i += 1  # skip the 's' after 'ms'
                    elif char == 's':
                        total_seconds += num  # seconds
                    elif char == 'm':
                        # Check if it's 'ms' or just 'm'
                        if i + 1 < len(time_str) and time_str[i + 1] == 's':
                            total_seconds += num / 1000  # milliseconds
                            i += 1  # skip the 's'
                        else:
                            total_seconds += num * 60  # minutes
                    elif char == 'h':
                        total_seconds += num * 3600  # hours
                    
                    current_number = ""
            
            i += 1
        
        return total_seconds
    
    def push_scope(self, params: Dict[str, Any] = None):
        """Push a new scope onto the call stack"""
        new_scope = params.copy() if params else {}
        self.call_stack.append(new_scope)
    
    def pop_scope(self):
        """Pop the current scope from the call stack"""
        if self.call_stack:
            self.call_stack.pop()
    
    def get_variable(self, name: str) -> Any:
        """Get variable value, checking local scope first, then global"""
        # Check local scopes (most recent first)
        for scope in reversed(self.call_stack):
            if name in scope:
                return scope[name]
        
        # Check global scope
        if name in self.variables:
            return self.variables[name]
        
        raise NameError(f'Variable {name} is not defined')
    
    def set_variable(self, name: str, value: Any):
        """Set variable value in the current scope"""
        if self.call_stack:
            self.call_stack[-1][name] = value
        else:
            self.variables[name] = value
    
    def update_variable(self, name: str, value: Any):
        """Update variable in its original scope"""
        # Check local scopes (most recent first)
        for scope in reversed(self.call_stack):
            if name in scope:
                scope[name] = value
                return
        
        # Update in global scope
        self.variables[name] = value
    
    def interpret(self, node: ASTNode) -> Any:
        method_name = f'visit_{type(node).__name__}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node: ASTNode):
        raise Exception(f'No visit_{type(node).__name__} method')
    
    def visit_Program(self, node: Program):
        result = None
        for statement in node.statements:
            result = self.interpret(statement)
        return result
    
    def visit_VarDeclaration(self, node: VarDeclaration):
        value = self.interpret(node.value)
        
        if node.op == "=":
            self.set_variable(node.name, value)
        elif node.op == "+=":
            try:
                current = self.get_variable(node.name)
            except NameError:
                current = 0
            self.update_variable(node.name, current + value)
        elif node.op == "-=":
            try:
                current = self.get_variable(node.name)
            except NameError:
                current = 0
            self.update_variable(node.name, current - value)
        elif node.op == "*=":
            try:
                current = self.get_variable(node.name)
            except NameError:
                current = 1
            self.update_variable(node.name, current * value)
        elif node.op == "/=":
            try:
                current = self.get_variable(node.name)
            except NameError:
                current = 1
            self.update_variable(node.name, current / value if value != 0 else 0)
        
        return self.get_variable(node.name)
    
    def visit_ShowStatement(self, node: ShowStatement):
        value = self.interpret(node.expression)
        print(value)
        return value
    
    def visit_InputStatement(self, node: InputStatement):
        prompt = node.prompt or ""
        
        if node.input_type == "input":
            return input(prompt)
        elif node.input_type == "inputStr":
            return input(prompt)
        elif node.input_type == "inputNum":
            try:
                return float(input(prompt))
            except ValueError:
                return 0.0
    
    def visit_BinaryOp(self, node: BinaryOp):
        left = self.interpret(node.left)
        right = self.interpret(node.right)
        
        if node.op == '+':
            return left + right
        elif node.op == '-':
            return left - right
        elif node.op == '*':
            return left * right
        elif node.op == '/':
            return left / right if right != 0 else 0
        elif node.op == '==':
            return left == right
        elif node.op == '!=':
            return left != right
        elif node.op == '<':
            return left < right
        elif node.op == '>':
            return left > right
        elif node.op == '<=':
            return left <= right
        elif node.op == '>=':
            return left >= right
        elif node.op == '&&':
            return left and right
        elif node.op == '||':
            return left or right
        else:
            raise Exception(f'Unknown binary operator: {node.op}')
    
    def visit_UnaryOp(self, node: UnaryOp):
        if node.postfix:
            # Postfix operators
            operand_value = self.interpret(node.operand)
            
            if isinstance(node.operand, Identifier):
                var_name = node.operand.name
                if node.op == '++':
                    self.update_variable(var_name, operand_value + 1)
                elif node.op == '--':
                    self.update_variable(var_name, operand_value - 1)
            
            return operand_value  # Return original value for postfix
        else:
            # Prefix operators
            if node.op in ('++', '--') and isinstance(node.operand, Identifier):
                var_name = node.operand.name
                current_value = self.get_variable(var_name)
                
                if node.op == '++':
                    new_value = current_value + 1
                else:  # '--'
                    new_value = current_value - 1
                
                self.update_variable(var_name, new_value)
                return new_value
            else:
                operand = self.interpret(node.operand)
                
                if node.op == '+':
                    return +operand
                elif node.op == '-':
                    return -operand
                elif node.op == '!':
                    return not operand
                else:
                    raise Exception(f'Unknown unary operator: {node.op}')
    
    def visit_Number(self, node: Number):
        return node.value
    
    def visit_String(self, node: String):
        return node.value
    
    def visit_Identifier(self, node: Identifier):
        return self.get_variable(node.name)
    
    def visit_Array(self, node: Array):
        return [self.interpret(element) for element in node.elements]
    
    def visit_Object(self, node: Object):
        result = {}
        for key, value_node in node.pairs:
            result[key] = self.interpret(value_node)
        return result
    
    def visit_ArrayAccess(self, node: ArrayAccess):
        array = self.interpret(node.array)
        index = self.interpret(node.index)
        
        if isinstance(array, (list, tuple, str)):
            try:
                return array[int(index)]
            except (IndexError, ValueError, TypeError):
                return None
        elif isinstance(array, dict):
            return array.get(str(index))
        else:
            raise TypeError(f'Cannot index {type(array)} with {type(index)}')
    
    def visit_PropertyAccess(self, node: PropertyAccess):
        obj = self.interpret(node.object)
        
        if isinstance(obj, dict):
            return obj.get(node.property)
        elif isinstance(obj, YaraInstance):
            # Check instance properties
            if node.property in obj.properties:
                return obj.properties[node.property]
            # Check for methods
            method = self.find_method(obj.yara_class, node.property)
            if method:
                # Return a bound method
                def bound_method(*args):
                    # Add 'this' to the scope
                    self.push_scope({'this': obj})
                    try:
                        # Create parameter mapping
                        params = dict(zip(method.params[1:], args))  # Skip 'this' parameter
                        for key, value in params.items():
                            self.set_variable(key, value)
                        
                        result = None
                        for stmt in method.body:
                            result = self.interpret(stmt)
                        return result
                    except ReturnException as ret:
                        return ret.value
                    finally:
                        self.pop_scope()
                
                return bound_method
        else:
            raise TypeError(f'Cannot access property {node.property} on {type(obj)}')
    
    def find_method(self, yara_class: YaraClass, method_name: str) -> Optional[MethodDeclaration]:
        """Find method in class hierarchy"""
        current = yara_class
        while current:
            if method_name in current.methods:
                return current.methods[method_name]
            current = current.parent
        return None
    
    def visit_InterpolatedString(self, node: InterpolatedString):
        result = ""
        live_parts = []
        
        for part in node.parts:
            if isinstance(part, StringPart):
                result += part.value
            elif isinstance(part, InterpolationPart):
                value = str(self.interpret(part.expression))
                
                if part.update_type == "live":
                    # For live updates, we'd need a more sophisticated display system
                    # For now, just append the value
                    result += value
                    live_parts.append((part.expression, len(result) - len(value), len(result)))
                elif part.update_type == "update":
                    # For update type, overwrite the current line
                    result += value
                else:
                    result += value
        
        # Store live parts for potential future updates
        if live_parts:
            self.live_displays[id(node)] = (result, live_parts)
        
        return result
    
    def visit_StringPart(self, node: StringPart):
        return node.value
    
    def visit_InterpolationPart(self, node: InterpolationPart):
        return str(self.interpret(node.expression))
    
    def visit_FunctionCall(self, node: FunctionCall):
        # Check if it's a user-defined function
        if node.name in self.functions:
            func_def = self.functions[node.name]
            
            # Evaluate arguments
            args = [self.interpret(arg) for arg in node.args]
            
            # Check parameter count
            if len(args) != len(func_def.params):
                raise TypeError(f'Function {node.name} expects {len(func_def.params)} arguments, got {len(args)}')
            
            # Create parameter mapping
            params = dict(zip(func_def.params, args))
            
            # Push new scope and execute function
            self.push_scope(params)
            try:
                result = None
                for stmt in func_def.body:
                    result = self.interpret(stmt)
                return result
            except ReturnException as ret:
                return ret.value
            finally:
                self.pop_scope()
        
        # Handle built-in functions
        elif node.name == "input":
            prompt = ""
            if node.args:
                prompt = str(self.interpret(node.args[0]))
            return input(prompt)
        elif node.name == "inputStr":
            prompt = ""
            if node.args:
                prompt = str(self.interpret(node.args[0]))
            return input(prompt)
        elif node.name == "inputNum":
            prompt = ""
            if node.args:
                prompt = str(self.interpret(node.args[0]))
            try:
                return float(input(prompt))
            except ValueError:
                return 0.0
        else:
            raise NameError(f'Function {node.name} is not defined')
    
    def visit_FunctionDeclaration(self, node: FunctionDeclaration):
        self.functions[node.name] = node
        return None
    
    def visit_WhileLoop(self, node: WhileLoop):
        result = None
        try:
            while self.interpret(node.condition):
                try:
                    for stmt in node.body:
                        result = self.interpret(stmt)
                except ContinueException:
                    continue
                except BreakException:
                    break
        except BreakException:
            pass
        return result
    
    def visit_ForLoop(self, node: ForLoop):
        iterable = self.interpret(node.iterable)
        result = None
        
        # Handle different iterable types
        if isinstance(iterable, str):
            # String iteration (char by char)
            items = list(iterable)
        elif isinstance(iterable, (list, tuple)):
            items = iterable
        elif isinstance(iterable, (int, float)):
            # Range from 0 to number
            items = list(range(int(iterable)))
        else:
            raise TypeError(f'Cannot iterate over {type(iterable)}')
        
        try:
            for item in items:
                self.set_variable(node.variable, item)
                try:
                    for stmt in node.body:
                        result = self.interpret(stmt)
                except ContinueException:
                    continue
                except BreakException:
                    break
        except BreakException:
            pass
        
        return result
    
    def visit_IfStatement(self, node: IfStatement):
        if self.interpret(node.condition):
            return self.interpret(node.then_stmt)
        
        # Check elif clauses
        for elif_condition, elif_stmt in node.elif_clauses:
            if self.interpret(elif_condition):
                return self.interpret(elif_stmt)
        
        # Execute else clause if present
        if node.else_stmt:
            return self.interpret(node.else_stmt)
        
        return None
    
    def visit_Block(self, node: Block):
        result = None
        for stmt in node.statements:
            result = self.interpret(stmt)
        return result
    
    def visit_ReturnStatement(self, node: ReturnStatement):
        value = None
        if node.value:
            value = self.interpret(node.value)
        raise ReturnException(value)
    
    def visit_BreakStatement(self, node: BreakStatement):
        raise BreakException()
    
    def visit_ContinueStatement(self, node: ContinueStatement):
        raise ContinueException()
    
    def visit_HaltStatement(self, node: HaltStatement):
        if self.interpret(node.condition):
            raise HaltException()
    
    def visit_RecallStatement(self, node: RecallStatement):
        # Save current value of variable
        if node.identifier in self.variables:
            self.recalled_values[node.identifier] = self.variables[node.identifier]
    
    def visit_ReviveStatement(self, node: ReviveStatement):
        # Restore recalled value
        if node.identifier in self.recalled_values:
            self.variables[node.identifier] = self.recalled_values[node.identifier]
    
    def visit_WaitStatement(self, node: WaitStatement):
        time_expr = self.interpret(node.time_expr)
        if isinstance(time_expr, str):
            seconds = self.parse_time_to_seconds(time_expr)
            time.sleep(seconds)
        return None
    
    def visit_EveryStatement(self, node: EveryStatement):
        time_expr = self.interpret(node.time_expr)
        if isinstance(time_expr, str):
            seconds = self.parse_time_to_seconds(time_expr)
            
            def run_every():
                while True:
                    time.sleep(seconds)
                    try:
                        self.interpret(node.statement)
                    except Exception as e:
                        print(f"Error in every statement: {e}")
                        break
            
            thread = threading.Thread(target=run_every, daemon=True)
            thread.start()
            self.every_threads.append(thread)
        
        return None
    
    def visit_TimeExpression(self, node: TimeExpression):
        return node.value
    
    def visit_PlotStatement(self, node: PlotStatement):
        # Simple text-based plotting
        data = self.interpret(node.expression)
        
        # Get plot options
        plot_type = "line"
        if "type" in node.options:
            plot_type = self.interpret(node.options["type"])
        
        if isinstance(data, list) and all(isinstance(x, (int, float)) for x in data):
            if plot_type == "bar":
                self.plot_bar_chart(data)
            else:
                self.plot_line_chart(data)
        else:
            print(f"Cannot plot data of type {type(data)}")
    
    def plot_line_chart(self, data: List[float]):
        """Simple ASCII line chart"""
        if not data:
            return
        
        max_val = max(data)
        min_val = min(data)
        height = 10
        
        if max_val == min_val:
            scale = 1
        else:
            scale = height / (max_val - min_val)
        
        print("\nLine Chart:")
        for h in range(height, -1, -1):
            line = ""
            for i, val in enumerate(data):
                normalized = int((val - min_val) * scale)
                if normalized == h:
                    line += "*"
                else:
                    line += " "
            print(f"{min_val + h/scale:6.2f} |{line}")
        
        print("       +" + "-" * len(data))
        print("        " + "".join(str(i % 10) for i in range(len(data))))
    
    def plot_bar_chart(self, data: List[float]):
        """Simple ASCII bar chart"""
        if not data:
            return
        
        max_val = max(data) if data else 1
        width = 40
        
        print("\nBar Chart:")
        for i, val in enumerate(data):
            bar_width = int((val / max_val) * width) if max_val > 0 else 0
            bar = "█" * bar_width
            print(f"{i:3d}: {bar} {val:.2f}")
    
    def visit_ClassDeclaration(self, node: ClassDeclaration):
        # Extract methods and properties
        methods = {}
        properties = {}
        
        for member in node.members:
            if isinstance(member, MethodDeclaration):
                methods[member.name] = member
            elif isinstance(member, PropertyDeclaration):
                properties[member.name] = self.interpret(member.value)
        
        # Get parent class if any
        parent = None
        if node.parent and node.parent in self.classes:
            parent = self.classes[node.parent]
        
        # Create class
        yara_class = YaraClass(node.name, parent, methods, properties)
        self.classes[node.name] = yara_class
        
        return None
    
    def visit_MethodDeclaration(self, node: MethodDeclaration):
        # Methods are handled by ClassDeclaration
        return node
    
    def visit_PropertyDeclaration(self, node: PropertyDeclaration):
        # Properties are handled by ClassDeclaration
        return node
    
    def visit_NewExpression(self, node: NewExpression):
        if node.class_name not in self.classes:
            raise NameError(f'Class {node.class_name} is not defined')
        
        yara_class = self.classes[node.class_name]
        instance = YaraInstance(yara_class)
        
        # Look for constructor method
        constructor = self.find_method(yara_class, "__init__")
        if constructor:
            # Call constructor
            args = [self.interpret(arg) for arg in node.args]
            self.push_scope({'this': instance})
            try:
                params = dict(zip(constructor.params[1:], args))  # Skip 'this'
                for key, value in params.items():
                    self.set_variable(key, value)
                
                for stmt in constructor.body:
                    self.interpret(stmt)
            except ReturnException:
                pass  # Constructors don't return values
            finally:
                self.pop_scope()
        
        return instance
    
    def visit_EventHandler(self, node: EventHandler):
        # Register event handler
        if node.event_type not in self.event_handlers:
            self.event_handlers[node.event_type] = []
        
        self.event_handlers[node.event_type].append(node)
        
        # Start event listening threads for certain events
        if node.event_type == "Timer":
            # Timer events need to be started with specific intervals
            pass
        
        return None
    
    def visit_SystemFunction(self, node: SystemFunction):
        if node.function_name == "getMouseClick":
            # Return last mouse click position (simulated)
            if self.mouse_clicks:
                return self.mouse_clicks.popleft()
            return {"x": 0, "y": 0}
        
        elif node.function_name == "getKeyPress":
            # Return last key press (simulated)
            if self.key_presses:
                return self.key_presses.popleft()
            return ""
        
        elif node.function_name == "readSensor":
            # Read sensor value
            sensor_name = ""
            if node.args:
                sensor_name = str(self.interpret(node.args[0]))
            
            if sensor_name in self.sensors:
                # Simulate sensor reading with some noise
                base_value = self.sensors[sensor_name]
                noise = random.uniform(-1, 1)
                return base_value + noise
            return 0.0
        
        elif node.function_name == "inputReady":
            # Check if input is available (always false in this simple implementation)
            return False
        
        elif node.function_name == "time.now":
            # Return current timestamp
            return time.time()
        
        else:
            raise NameError(f'System function {node.function_name} is not defined')
    
    def trigger_event(self, event_type: str, *args):
        """Manually trigger an event"""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                # Create parameter mapping
                params = dict(zip(handler.params, args))
                
                # Execute handler
                self.push_scope(params)
                try:
                    for stmt in handler.body:
                        self.interpret(stmt)
                except ReturnException:
                    pass  # Event handlers don't return values
                finally:
                    self.pop_scope()

def run_yara_code(code: str):
    """Run Yara code string"""
    try:
        lexer = Lexer(code)
        tokens = lexer.tokenize()
        
        parser = Parser(tokens)
        ast = parser.parse()
        
        interpreter = Interpreter()
        interpreter.interpret(ast)
        
    except HaltException:
        print("Program halted")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

def run_yara_file(filename: str):
    """Run Yara code from file"""
    try:
        with open(filename, 'r') as file:
            code = file.read()
        run_yara_code(code)
    except FileNotFoundError:
        print(f"File {filename} not found")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) > 1:
        # Run file
        run_yara_file(sys.argv[1])
    else:
        # Interactive mode
        print("Yara Language Interpreter v2.0")
        print("Enter 'exit' to quit")
        print("Features:")
        print("  - Variables, Functions, Loops, Arrays, Objects")
        print("  - String Interpolation, Time Operations")
        print("  - Classes and Inheritance")
        print("  - Event Handlers")
        print("  - Hardware/System Functions")
        print("  - Plotting Capabilities")
        print()
        
        interpreter = Interpreter()
        
        while True:
            try:
                code = input("yara> ")
                if code.strip().lower() == 'exit':
                    break
                if code.strip():
                    # For interactive mode, we need to handle single statements
                    try:
                        lexer = Lexer(code)
                        tokens = lexer.tokenize()
                        
                        parser = Parser(tokens)
                        ast = parser.parse()
                        
                        result = interpreter.interpret(ast)
                        
                        # Print non-None expression results
                        if result is not None and len(ast.statements) == 1:
                            stmt = ast.statements[0]
                            if not isinstance(stmt, (VarDeclaration, FunctionDeclaration, 
                                                   ClassDeclaration, ShowStatement)):
                                print(result)
                                
                    except HaltException:
                        print("Program halted")
                    except Exception as e:
                        print(f"Error: {e}")
                        
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except EOFError:
                print("\nGoodbye!")
                break

if __name__ == "__main__":
    main()