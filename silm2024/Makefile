
all: paper.pdf

paper.pdf: *.tex paper.bib
	${MAKE} -C figures/
	latexmk -pdf paper.tex

spelling: *.tex
	ispell -t -b -d american -p ./paper.dict *.tex

clean:
	${MAKE} -C figures/ clean
	rm -f paper.aux paper.bbl paper.blg paper.fdb_latexmk paper.fls \
          paper.log paper.out
	rm -f *.tex.bak

distclean: clean
	rm -f paper.pdf

