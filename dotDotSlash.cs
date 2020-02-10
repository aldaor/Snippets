//Due to .Net bug https://social.msdn.microsoft.com/Forums/en-US/e5aca106-9b7b-41cd-b68f-8c843f52210c/httpwebrequest-how-can-i-prevent-framework-45-to-unescape-2e-and-3a-characters-in-provided-url?forum=netfxbcl
//"/../" sequence in web request concatenated to "/" https://docs.microsoft.com/en-us/dotnet/api/system.uri?view=netframework-4.7.1
//The following code helped me

		public static object SyncObject = new object();
		private const int CompressPath = 0x800000;
		public static void LeaveMultipleSlashesAsIs(Uri uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException("uri");
            }
            FieldInfo fieldInfo = uri.GetType().GetField("m_Syntax", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fieldInfo == null)
            {
                throw new MissingFieldException("'m_Syntax' field not found");
            }
            object uriParser = fieldInfo.GetValue(uri);
            fieldInfo = typeof(UriParser).GetField("m_Flags", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fieldInfo == null)
            {
                throw new MissingFieldException("'m_Flags' field not found");
            }
            object uriSyntaxFlags = fieldInfo.GetValue(uriParser);
            // Clear the flag that we don't want
            uriSyntaxFlags = (int)uriSyntaxFlags & ~CompressPath;
		}

