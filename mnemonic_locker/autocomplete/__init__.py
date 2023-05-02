import random
import sys
from typing import List

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError
from mnemonic_locker.autocomplete.bip39 import words

# Créer un objet WordCompleter
completer = WordCompleter(words)


class InListValidator(Validator):
    def validate(self, document):
        text = document.text
        if text not in words:
            raise ValidationError(message='Please choose a valid bip39 word.')


# Fonction pour afficher le résultat de la saisie utilisateur
def show_result(result):
    print('Vous avez choisi :', result)


# Fonction pour utiliser prompt_toolkit avec autocomplétion
def prompt_with_autocomplete(index):
    result = prompt(f'Choose word #{index + 1}: ', validator=InListValidator(), completer=completer)
    return result


def build_seed_phrase(word_count: int = 24) -> List[str]:
    print("Enter your seed phrase !")
    indexes = list(range(word_count))
    random.shuffle(indexes)
    results = [""] * word_count
    for index in indexes:
        results[index] = prompt_with_autocomplete(index)
        clear_output()

    return results


def verify_seed_phrase(seed: List[str]):
    indexes = list(range(len(seed)))
    random.shuffle(indexes)
    print("Please verify your seed phrase before proceeding !")
    for index in indexes:
        print(f"Word #{index + 1} : " + seed[index], end='\r')
        answer = input("\nContinue? (y/n) ")
        clear_output(2)
        if answer.lower() == "n":
            clear_output(3)
            return False

    return True


def clear_output(line: int = 1):
    for i in range(line):
        # cursor up one line
        sys.stdout.write('\x1b[1A')
        # delete last line
        sys.stdout.write('\x1b[2K')
