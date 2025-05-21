from attack_convert.utils.evasions.insertion import evasive_insertion
from attack_convert.utils.evasions.substitution import evasive_substitution
from attack_convert.utils.evasions.omission import evasive_omission
from attack_convert.utils.evasions.reordering import evasive_reordering
from attack_convert.utils.evasions.recoding import evasive_recoding

def generate_all_evasions(original_command):
    return {
        "insertion": evasive_insertion(original_command),
        "substitution": evasive_substitution(original_command),
        "omission": evasive_omission(original_command),
        "reordering": evasive_reordering(original_command),
        "recoding": evasive_recoding(original_command)
    }
