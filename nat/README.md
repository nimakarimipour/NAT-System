## Usage

change your directory to here
put your information into **info.h**

to prevent any access by other users. Then you can use three other scripts as follows:

  - The **new.sh** for instantiating a new topology,
  - The **free.sh** for releasing the previously assigned topology instance,
    * Do not forget to free the instance when your simulation finished (required for log files flushing).
  - The **run.sh** for connecting your program to configured virtual node (if any).
    * Only use on Nat nodes.
