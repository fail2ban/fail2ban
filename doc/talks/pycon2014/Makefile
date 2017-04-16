all:: s.pdf

s.pdf::
	make -C../../images

%.pdf: %.tex
	pdflatex $<
