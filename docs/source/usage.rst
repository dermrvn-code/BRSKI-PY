Usage
=====

To use the BRSKI Python Implementation, follow these steps:

1. **Start the environment:**

   In every new terminal session, you need to start the environment by running the following command:

   .. code-block:: shell

      start_env.bat

2. **Generate the necessary certificates:**

   When starting the demonstrator for the first time, you need to generate all the necessary keys and certificates. To do so, follow these steps:

   1. **Tab into the 'Certificates' directory:**

      .. code-block:: shell

         cd Certificates

   2. **Run the script to generate all the necessary keys and certificates:**

      .. code-block:: shell

         py generate_certificates.py

3. **Adjust the configuration:**

   It might be necessary to adjust some configurations in the `config.ini` file.

   1. Open the `config.ini` file
   2. Revise the configurations, especially the ports of the different servers
   3. Check if the preset ports are already in use on your machine
   4. Adjust the ports if necessary
   5. Save the file

4. **Start the demonstrator:**

   - Call the `start_all.py` script if already in environment:

     .. code-block:: shell

        py start_all.py

   - Or start the demonstrator by just opening the `start.bat` file:

     .. code-block:: shell

        start.bat
