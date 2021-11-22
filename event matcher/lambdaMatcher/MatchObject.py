from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

def get_multipliers():
    path = Path(__file__).parent / "keyword_scores.yaml"

    with open(path) as file:
        # The FullLoader parameter handles the conversion from YAML
        # scalar values to Python the dictionary format
        scores = yaml.load(file, Loader=yaml.FullLoader)
        multipliers = defaultdict(lambda: 1.0, scores)
        return multipliers


multiplier = get_multipliers()

# multiplier = defaultdict(lambda: 1.0)
# multiplier["name.common"] = 1
# multiplier["name.first"] = 0.55
# multiplier["name.last"] = 0.75
# multiplier["name.middle"] = 0.56
# multiplier['organisation.title'] = 0.65
# multiplier["email"] = 1.0
# multiplier['email.work'] = 1
# multiplier["organisation.name"] = .75
# multiplier["organisation.role"] = .65
# multiplier["location.premise"] = .75
# multiplier["location.street_name"] = .66
# multiplier["location.country"] = .51
# multiplier['location.postal_town'] = .55
# multiplier['location.postal_code'] = .60
# multiplier["location.lat"] = 1.0
# multiplier["location.lng"] = 1.0
# multiplier['netloc.as_number'] = .51
# multiplier['social_media.owler'] = .55

@dataclass
class MatchObject:
    """

    """
    asset_id: str
    case_id: str
    asset_score: str
    matched: str
    keyword_name: str
    start_pos: int
    end_pos: int

    def __lt__(self, other):
        return self.start_pos < other.start_pos

    def validate_match(self, text_data):
        """ This function validates each matched string and checks that it is surounded with valid characters"""
        if self.keyword_name == ['location.country_short']:
            valid_chars = ["\"", ".", " "]
        elif 'url' in self.keyword_name or self.keyword_name == "name.common":
            valid_chars = ['/', '.', " ", "(", ")", "[", "]", "\r", "\n", "@", "\t", "!"]
        else:
            valid_chars = [' ', ',', "." " ", "\r", "\n", "@", "\t", "!", "\"", "'", "(", ")", "[", "]"]
        try:
            if text_data[self.end_pos + 1] in valid_chars:
                if text_data[self.start_pos - 1] in valid_chars:
                    return True
                else:
                    return False
            else:
                return False

        except IndexError:
            return False

    @property
    def score(self):
        """
        returns a base score of the matched string calculated based on the uniqueness of the string and the length of
        the string.
        """

        len_score = .2 * len(self.matched)

        if len_score > 1.0:
            len_score = 1.0
        score = len_score * multiplier[self.keyword_name]
        return score

