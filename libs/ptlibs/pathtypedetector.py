import os

class PathTypeDetector:
    DOCUMENT_EXTENSIONS = [
        # Text files
        '.txt',
        # Microsoft Word documents
        '.doc', '.docx',
        # OpenOffice/LibreOffice documents
        '.odt',
        # PDF documents
        '.pdf',
        # Rich Text Format documents
        '.rtf',
        # WordPerfect documents
        '.wpd',
        # Microsoft Works documents
        '.wps',
        # Apple Pages documents
        '.pages',
        # eBooks
        '.epub',
        # Spreadsheets
        '.xls', '.xlsx', '.ods', '.csv',
        # Presentations
        '.ppt', '.pptx', '.odp', '.key',
        # Markdown documents
        '.md',
        # LaTeX documents
        '.tex',
        # LyX documents
        '.lyx',
        # AbiWord documents
        '.abw', '.zabw', '.awt', '.zawt', '.bzabw',
        # DjVu documents
        '.djvu',
        # XPS documents
        '.xps',
        # OXPS documents
        '.oxps',
        # Flat ODT documents
        '.fodt',
        # Unified Office Format Text documents
        '.uot',
    ]


    IMAGE_EXTENSIONS = [
        # Raster images
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.ico',
        '.psd', '.xcf', '.webp', '.hdr', '.pic', '.pct', '.exr',
        '.pcx', '.tga', '.dds', '.sgi', '.cgm', '.dxf', '.wmf',
        '.emf', '.pbm', '.pgm', '.ppm', '.xbm', '.xpm', '.ras',
        '.iff', '.lbm', '.pcd', '.pcds', '.mng', '.tga', '.wpg',
        '.msp', '.pdd', '.dib', '.dcx', '.cut', '.pdn', '.pnm',
        '.pntg', '.psp', '.sgi', '.sxd', '.sxw', '.sxc', '.sxi',
        '.sxd', '.sxm', '.sxg', '.sxv', '.sxw', '.sxg',
        # Vector images
        '.svg', '.ai', '.eps', '.cdr', '.cdt', '.cpt', '.cws',
        '.xar', '.mmp', '.odg', '.otg', '.stc', '.sxd', '.sda',
        '.sdd', '.sdp', '.sds', '.sdw', '.sxm', '.vsd', '.vsdx',
        '.vsdm', '.vsd', '.vst', '.vss', '.vssx', '.vssm', '.vstx',
        '.vstm', '.vsw', '.vsx', '.vtx', '.vsx', '.vsdm', '.vsdm',
        # 3D images
        '.3ds', '.dae', '.obj', '.stl', '.skp', '.skb', '.skc',
        '.skm', '.skx', '.skd', '.skf', '.skv', '.skt',
        # Other image formats
        '.apng', '.bpg', '.dcm', '.ecw', '.exr', '.fits', '.flif',
        '.jp2', '.jpegxr', '.kra', '.mng', '.pgf', '.qtvr', '.raw',
        '.sgi', '.tga', '.tiff', '.ufo', '.wdp',
    ]


    CONFIG_EXTENSIONS = [
        # Configuration files
        '.cfg', '.ini', '.conf', '.properties', '.props', '.rc', '.cf', '.cnf', '.reg', '.settings',
        # Information files
        '.inf', '.info', '.stat', '.dat', '.reg', '.prefs', '.pref'
    ]


    JSON_EXTENSIONS = [
        '.json', '.jsn', '.jason', '.geojson'
    ]


    XML_EXTENSIONS = [
        '.xml', '.xsd', '.xsl', '.xslt', '.dtd', '.ent', '.xul'
    ]


    BACKUP_EXTENSIONS = [
        # Backup files
        '.bak', '.backup', '.bk', '.bkp', '.swp', '.sav', '.old', '.tmp', '.temp', '.copy',
        '.snap', '.versions', '.recycle', '.recycler', '.recycled', '.trash', '.deleted',
    ]


    def __init__(self, path: str):
        """Create object for URL path type determination

        Args:
            path (str): path to be determined
        """
        # Get the file extension using the splitext function
        self.path = path
        self.resource_name, self.extension = os.path.splitext(path)


    def get_type(self) -> str:
        """Determine the path type based on the extension name.

        Returns:
            A string representing the file type.
        """

        if self.is_directory():
            return "directory"
        elif self.is_robots_file():
            return "robots.txt"
        elif self.is_sitemap():
            return "sitemap"
        elif self.is_document():
            return 'document'
        elif self.is_image():
            return 'image'
        elif self.is_config():
            return 'config'
        elif self.is_backup():
            return 'backup'
        elif self.is_json():
            return 'json'
        elif self.is_xml():
            return 'xml'
        else:
            return None


    def is_directory(self):
        """Determine if the path is a directory."""
        return self.extension == ""


    def is_document(self):
        """Determine if the path is a document."""
        return self.extension in self.DOCUMENT_EXTENSIONS


    def is_image(self):
        """Determine if the path is an image."""
        return self.extension in self.IMAGE_EXTENSIONS


    def is_config(self):
        """Determine if the path is a configuration file."""
        return self.extension in self.CONFIG_EXTENSIONS


    def is_backup(self):
        """Determine if the path is a backup file."""
        return self.extension in self.BACKUP_EXTENSIONS


    def is_json(self):
        """Determine if the path is a JSON file."""
        return self.extension in self.JSON_EXTENSIONS


    def is_xml(self):
        """Determine if the path is an XML file."""
        return self.extension in self.XML_EXTENSIONS


    def is_robots_file(self):
        """Determine if the path is a robots.txt file."""
        return self.path == "robots.txt"


    def is_sitemap(self):
        """Determine if the path is a sitemap.xml file."""
        return self.path == "sitemap.xml"