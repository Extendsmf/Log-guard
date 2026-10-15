from src.logguard.parser import parser
from src.logguard.engine import DetectionEngine
from src.logguard.dispatcher import AlertDispatcher
from src.logguard.reader import read_gen
import argparse
import sys

arg_parser = argparse.ArgumentParser()

arg_parser.add_argument("--file", type=str, required=True, help="Путь к файлу с логами")
arg_parser.add_argument("--follow", action="store_true", help="Следовать за новыми строками в реальном времени (tail -f)")
args = arg_parser.parse_args()

filepath = args.file
follow = args.follow

engine = DetectionEngine() 
dispatcher = AlertDispatcher()

try:
    for line in read_gen(filepath, follow):
        event = parser(line)
        if event:
            alerts = engine.detect(event)
            for alert in alerts:
                dispatcher.dispatch(alert)
except KeyboardInterrupt:
        print('Interrupted')
        sys.exit(0)