============
yacas_kernel
============

Native yacas_ kernel for Jupyter_, an interactive data science and scientific
computing environment.

.. _yacas: http://www.yacas.org
.. _Jupyter: http://jupyter.org


Installation
============
 
1. download sources from https://github.com/grzegorzmazur/yacas_kernel/archive/master.zip
2. build and install

  .. code:: bash

    unzip master.zip
    cd yacas_kernel-master
    mkdir build
    cd build
    cmake -DYACAS_PREFIX:PATH=<yacas installation root> -DCMAKE_INSTALL_PREFIX:PATH=<kernel installation root> ..
    make
    make install

  where `<yacas installation root>` and `<kernel installation root>` have to be
  substituded with actual paths

3. configure jupyter to use yacas_kernel
  
  - :code:`mkdir -p ~/.ipython/kernels/yacas/`
  - create file `~/.ipython/kernels/yacas/kernel.json` containing

    .. code:: yaml

      {
        "display_name": "Yacas", 
        "language": "yacas", 
        "argv": [
            "<kernel installation root>/bin/yacas_kernel", 
            "{connection_file}",
            "<yacas installation root>/share/yacas/scripts"
        ]
      }

    where `<yacas installation root>` and `<kernel installation root>` have to
    be substituded with actual paths

