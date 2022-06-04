RST2HTML = rst2html
OPTIONS =
SOURCE = pantv.html tvapi.html

.SUFFIXES: .rst .html
.rst.html:
	$(RST2HTML) $(OPTIONS) $< $@

all: $(SOURCE)

clean:
	rm -f $(SOURCE)
