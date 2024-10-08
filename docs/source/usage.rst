Usage
=====

To use the BRSKI Python Implementation, follow these steps:

1. **Start the environment:**

   In every new terminal session, you need to start the environment by running the following command:

   .. code-block:: shell

      start_env.bat

2. **Adjust the configuration:**

   It might be necessary to adjust some configurations in the `config.ini` file.

   1. Open the `config.ini` file
   2. Revise the configurations, especially the ports of the different servers
   3. Check if the preset ports are already in use on your machine
   4. Adjust the ports if necessary
   5. Save the file

3. **Generate the necessary certificates:**

   Be sure to set the correct ports beforehand, as some certificates get embedded URLs, with the ports specified in the config.ini.
   
   When starting the demonstrator for the first time, you need to generate all the necessary keys and certificates.  
   To do so, follow these steps:
   
   1.  **Run the script to generate all the necessary keys and certificates:**

      .. code-block:: shell

         py brski-py/Certificates/generate_certificates.py

4. **Start the demonstrator:**

   - Call the `start_all.py` script if already in environment:

     .. code-block:: shell

        py start_all.py

   - Or start the demonstrator by just opening the `start.bat` file:

     .. code-block:: shell

        start.bat

5. **Reset the demonstrator:**

   If you want to reset the demonstrators logs and saved statuses, you can do so by running the `brski-py/reset_process.py` script: 

     .. code-block:: shell

        py brski-py/reset_process.py
