import re
def single_line_suggestion(log):
	split = log.split()
	if "-" in split[0]:
		split = split[1:]
	filtered = [x for x in split if ((not "." in x[:-1]) and (not ":" in x[:-1]))]
	joined = " ".join(filtered)
	return [x.strip() for x in re.split(r'[.:;\[\]]', joined) if x.strip()]

def common_substrings(strings, disallowed_chars="."):
	""" For a list of strings, find substrings common beteween all of them.
		
		strings: the list of strings
		disallowed_chars: ignore any words which include specific disallowed characters.
	"""
	strings = [line.split() for line in strings]
	common_words = strings[0]

	for line in strings:
		remaining_words = [x for x in common_words]
		idx = 0
		out = []
		for word in line:
			try:
				for char in disallowed_chars:
					if char in word:
						raise ValueError()
				idx = remaining_words[idx:].index(word)+1
			except ValueError:
				idx += 1
				out.append(None)
				continue
			out.append(word)
		common_words = out
	result = [[]]
	for word in common_words:
		if word is None:
			result.append([])
		else:
			result[-1].append(word)
	return [' '.join(x) for x in result if x]

