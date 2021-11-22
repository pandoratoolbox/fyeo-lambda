import dataclasses

from typing import List

from chalicelib.lambdaMatcher.MatchObject import MatchObject


@dataclasses.dataclass
class Snippet:
    start_pos: int
    end_pos: int
    cut: str
    matches: List[MatchObject]
    offset: int = 150

    def __post_init__(self):
        self.len = len(self.cut)

    def score(self):
        """
        Returns a score of the matches in the snippet
        :return:
        """
        prob = bayesian_probability(self.matches)
        return prob

    def append_match(self, match: MatchObject, text_data: str):
        """
        Appends a match object to the snippet
        :param text_data:
        :param match:
        :return:
        """
        if match.start_pos - self.offset < self.start_pos:
            self.start_pos = match.start_pos - self.offset
            if self.start_pos < 0:
                self.start_pos = 0

        if match.end_pos + self.offset > self.end_pos:
            self.end_pos = match.end_pos + self.offset
            if self.end_pos > len(text_data):
                self.end_pos = len(text_data)

        self.cut = text_data[self.start_pos: self.end_pos]
        self.matches.append(match)
        self.len = len(self.cut)

    def boundary(self):
        return self.start_pos, self.end_pos

    @classmethod
    def from_match(cls, match: MatchObject, text_data: str):
        startpos = match.start_pos - cls.offset
        if startpos < 0:
            startpos = 0

        endpos = match.end_pos + cls.offset
        if endpos > len(text_data):
            endpos = len(text_data)


        return cls(startpos, endpos, cut=text_data[startpos:endpos], matches=[match])

    def intersects(self, match: MatchObject):
        """
        returns true if a match object intersects with the Snippet
        :param match:
        :return:
        """
        if match.end_pos + 150 < self.end_pos + 150 or match.start_pos > -150 > self.start_pos:
            return True
        else:
            return False

    def to_dict(self):
        self.len = len(self.cut)
        return dataclasses.asdict(self)

    def fix_base_offset(self):
        """
        function that fixes all start and references so that multi matching terms has the correct index into the snippet.
        :return:
        """
        for match in self.matches:
            match.start_pos -= self.start_pos
            match.end_pos -= self.start_pos


def bayes_formula(current_match_probability, current_no_match_probability, match_probability):
    no_match_probability = 1 - match_probability

    current_match_probability = (match_probability * current_match_probability) / (
            (match_probability * current_match_probability) + (no_match_probability * current_no_match_probability)
    )

    current_no_match_probability = 1 - current_match_probability
    return current_match_probability, current_no_match_probability


def bayesian_probability(match_probability_array):
    match_probability = 0.5
    no_match_probability = 0.5
    types_done = [] # a list of keywords already encountered

    for match in match_probability_array:
        if match.keyword_name in types_done:
            continue

        if match.score > .999:
            return match.score

        # print("[scoring] cur_prob:%.1f | score: %.1f asset:%s keyword: %s [%s]" %
        #       (match_probability, match.score, match.asset_id, match.keyword_name, match.matched))

        match_probability, no_match_probability = bayes_formula(
            match_probability,
            no_match_probability,
            match.score)
        types_done.append(match.keyword_name)

    return match_probability