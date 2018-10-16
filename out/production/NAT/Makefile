SUB_NAME = PA1_java
all:
	javac *.java ir/sharif/ce/partov/machine/*.java ir/sharif/ce/partov/user/*.java ir/sharif/ce/partov/utils/*.java ir/sharif/ce/partov/base/*.java
clean:
	rm *.class ir/sharif/ce/partov/machine/*.class ir/sharif/ce/partov/user/*.class ir/sharif/ce/partov/utils/*.class ir/sharif/ce/partov/base/*.class
archive:
	zip -r ${SUB_NAME}_`date +%s`.zip *.java run.sh free.sh new.sh Makefile ir/sharif/ce/partov/machine/*.java ir/sharif/ce/partov/user/*.java ir/sharif/ce/partov/utils/*.java ir/sharif/ce/partov/base/*.java
