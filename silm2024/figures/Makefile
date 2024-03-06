SVG_FILES   = $(shell ls -- *.svg)
GRAPHICS    = $(SVG_FILES:.svg=.pdf)

all: ${GRAPHICS}

%.pdf: %.svg
	inkscape $< -o $@

clean:
	rm -f ${GRAPHICS}

