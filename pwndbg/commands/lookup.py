# -*- coding: utf-8 -*-
import sys
import re
import pwndbg.commands
import pwndbg.arguments
import pwndbg.color
import pwndbg.color.context as C
import pwndbg.color.disasm as D
import pwndbg.color.nearpc as N
import pwndbg.color.theme
import pwndbg.commands.comments
import pwndbg.config
import pwndbg.disasm
import pwndbg.functions
import pwndbg.ida
import pwndbg.regs
import pwndbg.strings
import pwndbg.symbol
import pwndbg.ui
import pwndbg.vmmap
from pwndbg.color import message

# def lookup(self, *arg):
#     """
#     Search for all addresses/references to addresses which belong to a memory range
#     Usage:
#         MYNAME address searchfor belongto
#         MYNAME pointer searchfor belongto
#     """
#     (option, searchfor, belongto) = normalize_argv(arg, 3)
#     if option is None:
#         self._missing_argument()

#     result = []
#     if searchfor is None:
#         searchfor = "stack"
#     if belongto is None:
#         belongto = "binary"

#     if option == "pointer":
#         msg("Searching for pointers on: %s pointed to: %s, this may take minutes to complete..." % (searchfor, belongto))
#         result = peda.search_pointer(searchfor, belongto)
#     if option == "address":
#         msg("Searching for addresses on: %s belong to: %s, this may take minutes to complete..." % (searchfor, belongto))
#         result = peda.search_address(searchfor, belongto)

#     text = peda.format_search_result(result, 0)
#     pager(text)

#     return
#     lookup.options = ["address", "pointer"]

