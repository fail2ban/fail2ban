all:: pics

# Optionally some PICS could be ignored. By default XXX ones.
# PICS_IGNORE must contain a rule for grep
PICS_IGNORE ?= "XXX"

# For every .svg we must have a pdf
PICS=$(shell find . -iname \*svg \
	| sed -e 's/svg/pdf/g' -e 's/\([^\]\)\([ \t:]\)/\1\\\\\2/g' \
	| grep -v -e $(PICS_IGNORE) \
	| grep -v -e neuropy_history_tuned )

pics: $(PICS)

clean::
	for p in *.svg; do rm -f $${p%*.svg}.{pdf,eps,png}; done

#
# Inkscape rendered figures
#
%.pdf: %.svg ignore-%.pdf
	@echo "Rendering $@"
	@inkscape -z -f "$<" -A "$@"

%.eps: %.svg ignore-%.eps
	@echo "Rendering $@"
	@inkscape -z -T -f "$<" -E "$@"

%.png: %.svg ignore-%.png
	@echo "Rendering $@"
	@inkscape -z -f "$<" -e "$@" -d 150

.PHONY: ignore-%
ignore-%:
	@grep -q "^$*$$" .gitignore || { \
	  echo "$*" >> .gitignore; echo "Ignore $@"; }

.PHONY: all pics
