
all:
	@if [ -z "${RESDIR}" ] ; then echo "RESDIR not set"; exit 1; fi
	@if [ -z "${NIC0}" ] ; then echo "NIC0 not set"; exit 1; fi
	@if [ -z "${NIC1}" ] ; then echo "NIC1 not set"; exit 1; fi
	@if [ -z "${NIC2}" ] ; then echo "NIC2 not set"; exit 1; fi
	@if [ -z "${NIC3}" ] ; then echo "NIC3 not set"; exit 1; fi
	mkdir -p ${RESDIR}
	RESDIR=$(RESDIR) NIC0=$(NIC0) NIC1=$(NIC1) NIC2=$(NIC2) NIC3=$(NIC3) make $(RESDIR)/done

$(RESDIR)/done:
	for i in *.dist; do \
		target=`expr $$i : '\(.*\).dist'`; \
		sed \
		    -e 's/NIC0HEXADDR/${NIC0HEXADDR}/g' \
		    -e 's/NIC1HEXADDR/${NIC1HEXADDR}/g' \
		    -e 's/NIC0/${NIC0}/g' -e 's/NIC1/${NIC1}/g' \
		    -e 's/NIC2/${NIC2}/g' -e 's/NIC3/${NIC3}/g' \
		    -e 's/_/ /g' \
		    $$i > $(RESDIR)/$${target}; \
		cc=`egrep CKSUM $(RESDIR)/$${target} | wc -l`; \
		if [ $${cc} -ne 0 ] ; then \
			mv $(RESDIR)/$${target} $(RESDIR)/$${target}.tmp; \
			perl ../fillcksum.pl $(RESDIR)/$${target}.tmp > \
			     $(RESDIR)/$${target}; \
		fi \
	done
	touch ${RESDIR}/done

clean:
	for i in */done; do \
		d=`dirname $$i`; \
		if [ -d "$$d" ] ; then \
			echo $$d; \
		fi \
	done
