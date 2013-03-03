#
# Makefile for adm6
#
BACKUP = ~/adm6.tbz

default:	tests

sync:
	@git push -v --mirror git+ssh://jhselber@scm.evolvis.org/scmrepos/git/adm6/adm6.git

run:
	@python device.py 2>&1
	#@python device.py 2>&1 | more

new:
	make clean
	make landscape

landscape:
	@python demo.py 
	ln -sf ~/.adm6.conf global-cfg
	ln -sf ~/adm6/desc desc
	ln -sf ~/adm6/desc/adm6/output out-adm6
	ln -sf ~/adm6/desc/ns/output out-ns
	ln -sf ~/adm6/desc/obi-wan/output out-ow
	ln -sf ~/adm6/desc/www/output out-www
	ln -sf ~/adm6/desc/r-ex/output out-r-ex

tests:
	@nosetests -v --with-coverage  adm6/hostnet6.py

clean:
	rm -rf *~
	rm -f *.pyc adm6/*pyc
	rm -f desc out-adm6 out-ns out-ow out-www out-r-ex global-cfg out-o6
	rm -rf ~/adm6/

back:
	make clean
	rm -f $(BACKUP)
	tar cjvf - ./* ./.git* > $(BACKUP)

# EoF
