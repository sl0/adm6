#
# Makefile for adm6
#
default:	test_all

test_all:
	@make demo
	@make noses
	@make clean 2>&1 >/dev/null
	@echo "all done"

noses:
	@nosetests -v --cover-package=adm6 --with-coverage 2>&1

run:
	@python adm6/device.py 2>&1

demo:
	@python tests/prep_demo.py
	ln -sf ~/.adm6.conf global-cfg
	ln -sf ~/adm6/etc etc
	ln -sf ~/adm6/desc desc
	ln -sf ~/adm6/desc/adm6/output out-adm6
	ln -sf ~/adm6/desc/ns/output out-ns
	ln -sf ~/adm6/desc/obi-wan/output out-ow
	ln -sf ~/adm6/desc/www/output out-www
	ln -sf ~/adm6/desc/r-ex/output out-r-ex
	@echo
	@echo "go ahead: python adm6/device.py"
	@echo
	@echo "then inspect those out-xyz"
	@echo
	@echo "have fun!"

docs:
	(cd doc; make html; cd -)

clean:
	(cd doc; make clean ; cd - )
	rm -rf *~
	rm -f *.pyc adm6/*pyc tests/*pyc
	rm -f out-adm6 out-ns out-ow out-www out-r-ex global-cfg
	rm -rf etc desc ~/adm6/ ~/.adm6.conf

# EoF
