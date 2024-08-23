<!-- @format -->

<p align="center">
  <img src="https://github.com/user-attachments/assets/1503239f-b992-4e11-a61c-d19294b00af4" /><br/><br/>
  <strong>Bootstrapping Remote Secure Key Infrastructure in Python</strong><br/><br/>
  
  <a href="https://python.org/downloads/release/python-3123/">
  <a href="https://python.org/downloads/release/python-3123/">
    <img src="https://img.shields.io/badge/-Python_3.12.3-3776AB?style=for-the-badge&logo=python&logoColor=white">
  </a>
  
  <a href="https://github.com/dermrvn-code/BRSKI-PY">
    <img src="https://img.shields.io/github/last-commit/dermrvn-code/BRSKI-PY?style=for-the-badge">
  </a>

  <a href="https://github.com/dermrvn-code/BRSKI-PY?tab=MIT-1-ov-file#readme">
    <img src="https://img.shields.io/github/license/dermrvn-code/BRSKI-PY?style=for-the-badge">
  </a>

  <img src="https://img.shields.io/badge/Status-Tech_Demo-red?style=for-the-badge">
</p>

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Generate Docs](#generate-docs)

## Installation

To install the BRSKI Python Implementation, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/dermrvn-code/BRSKI-PY
   ```

2. Navigate to the project directory:

   ```shell
   cd BRSKI-PY
   ```

3. Install the required dependencies:

   ```shell
   py install.py
   ```

Now everything is successfully installed and the BRSKI Python Implementation can be used.

## Usage

To use the BRSKI Python Implementation, follow these steps:

1. Start the environment:

   In every new terminal session, you need to start the environment by running the following command:

   ```shell
   start_env.bat
   ```

2. Generate the necessary certificates:

   When starting the demonstrator for the first time, you need to generate all the necessary keys and certificates. To do so, follow these steps:

   1. Tab into the 'Certificates' directory:

   ```shell
   cd Certificates
   ```

   2. Run the script to generate all the necessary keys and certificates:

   ```shell
   py generate_certificates.py
   ```

3. Adjust the configuation

   It might be necessary to adjust some configurations in the config.ini file.

   1. Open the config.ini file

   2. Revise the configurations, especially the ports of the different servers

   3. Check if the preset ports are already in use on your machine

   4. Adjust the ports if necessary

   5. Save the file

4. Start the demonstrator:

   - Call the start_all.py script if already in environment:

     ```shell
     py start_all.py
     ```

   - Or start the demonstrator by just opening the start.bat file:

     ```shell
     start.bat
     ```

## Generate Docs

To generate a sphinx documentation for the BRSKI Python Implementation, follow these steps:

1. Start the virtual environment:

   ```shell
   start_env.bat
   ```

2. Navigate to the docs directory:

   ```shell
   cd docs
   ```

3. Build the documentation:

   ```shell
   build_docs.bat
   ```

4. If the documentation was successfully built, you can find the HTML files in the `docs/build/html` directory.

[(Back to top)](#table-of-contents)
