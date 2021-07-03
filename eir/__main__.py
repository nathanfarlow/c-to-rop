from .parser import Parser
from pprint import pprint

if __name__ == "__main__":
    parser = Parser(open("elvm/test.s"))
    pprint(parser.data_elements)
    pprint(parser.text_elements)
