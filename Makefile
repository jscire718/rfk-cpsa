# Makefile rules for CPSA

# Suggested CPSA flags include a memory use limit:
# CPSAFLAGS = +RTS -M512m -RTS

TSTS	:= $(patsubst %.scm,%.txt,$(wildcard *.scm)) \
		$(patsubst %.lsp,%.txt,$(wildcard *.lsp))
CPSAFLAGS = +RTS -N8 -RTS   ## --limit=3000
CPSATIME = time

# Analyze protocols for shapes
%.txt:		%.scm
	$(CPSATIME) cpsa $(CPSAFLAGS) -o $@ $<

# Analyze protocols for shapes, but don't fail when CPSA does
%.txt:		%.lsp
	-$(CPSATIME) cpsa $(CPSAFLAGS) -o $@ $<

# Extract shapes
%_shapes.txt:	%.txt
	cpsashapes $(SHAPESFLAGS) -o $@ $<

# Extract shape analysis sentences
%_logic.text:	%.txt
	cpsasas $(LOGICFLAGS) -o $@ $<

# Annotate shapes
%_annotations.txt:	%_shapes.txt
	cpsaannotations $(ANNOTATIONSFLAGS) -o $@ $<

# Compute protocol parameters
%_parameters.txt:	%_shapes.txt
	cpsaparameters $(PARAMETERSFLAGS) -o $@ $<

# Visualize output using the expanded format (default)
%.xhtml:	%.txt
	cpsagraph $(GRAPHFLAGS) -o $@ $<

# Visualize output using the compact format
%.svg:		%.txt
	cpsagraph -c -o $@ $<

# Visualize output using the LaTeX format
%.tex:		%.txt
	cpsagraph -l -m 62 -o $@ $<

.PRECIOUS:	%.txt %_shapes.txt %_annotations.txt

all:	$(patsubst %.txt,%.xhtml,$(TSTS)) \
		$(patsubst %.txt,%_shapes.xhtml,$(TSTS))

clean:
	-rm *.txt *.xhtml
