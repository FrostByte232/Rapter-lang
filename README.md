# Rapter-lang
A beginner friendly, general purpose programming language that excels at creating GUIs and controlling things (games, apps, hardware, etc).

Core Goals

*Target Users: Beginners (including yourself)
*Syntax Style: "Logically simple" - not English-like, more JavaScript-inspired but cleaner
*Platform Support: Cross-platform with minimal dependencies (Windows, Linux, etc.)
*File Extension: .rapt

Development Plan
Phase 1: Core Language (Rapter 0.1)

*Variables: variable:name = value or var:name = value
*Functions: function:myFunc or function:myFunc(args)
*Print: say()
*Basic math and operations
*Error handling with helpful messages

Phase 2: GUI Integration

*Window creation with Tkinter backend
*First project: GUI Calculator
*Buttons, text input, basic layouts

Phase 3: Advanced Features

*Drawing/canvas capabilities (for games)
*Eventually compile to native binaries
*Self-hosting (write Rapter compiler in Rapter)

Technical Approach

*Start: Interpreted language built with Python
*Parser: Grammar-first approach (define syntax rules before implementation)
*GUI Library: Tkinter initially, custom later
*First Cool Feature: Create popup windows

Next Steps

1. Define complete grammar rules
2. Write example .rapt programs
3. Build basic tokenizer/lexer
4. Create simple interpreter
5. Add GUI window capabilities
